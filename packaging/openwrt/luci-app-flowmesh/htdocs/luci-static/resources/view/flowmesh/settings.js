// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require form';
'require poll';
'require uci';
'require ui';
'require network';
'require flowmesh.common as fm';
'require flowmesh.state as fmstate';

// Services -> FlowMesh -> Settings: what this router shares, exit nodes, mesh names for the LAN and
// the advanced switches, as one form. "Save & Apply" commits /etc/config/flowmesh and pushes it to
// the daemon (flowmesh-luci apply), the same path Overview's Start takes (fm.applyConfig).
//
// Form titles and descriptions are rendered as markup by LuCI: they only ever hold fixed text.
// Anything from the mesh (names, networks, states) goes into nodes made with fm.el().

var el = fm.el, setContent = fm.setContent, helper = fm.helper;

// true for a network that can be shared, else the reason.
function routeError(value) {
	var r = fmstate.validateRoute(value);

	if (r.ok)
		return true;

	switch (r.error) {
	case 'default':
		return _('A default route cannot be shared. To carry other devices\' Internet traffic, use "Act as exit node".');
	case 'mesh':
		return _('This network overlaps the mesh\'s own addresses.');
	default:
		return _('Enter a network as address/prefix length, such as 192.168.1.0/24.');
	}
}

function sameSet(a, b) {
	return a.length == b.length && a.every(function(x) { return b.indexOf(x) >= 0; });
}

// The form controls of a LuCI widget (its node, or the inputs/selects inside it).
function controls(widget) {
	var n = widget && widget.node;

	if (!n)
		return [];

	if (n.matches && n.matches('input, select'))
		return [ n ];

	return Array.prototype.slice.call(n.querySelectorAll('input, select'));
}

function setDisabled(widget, on) {
	controls(widget).forEach(function(c) { c.disabled = on; });
}

return view.extend({
	load: function() {
		return Promise.all([
			helper([ 'status' ]),
			helper([ 'exitstate' ]),
			uci.load('flowmesh'),
			L.resolveDefault(network.getNetwork('lan'), null)
		]);
	},

	render: function(data) {
		var self = this, m, s, o;

		this.status = data[0];
		this.exitState = data[1];
		this.lan = data[3];
		this.sum = fmstate.summarize(this.status);
		this.snapshot();

		var mode = fm.modeOf(this.sum);

		if (mode != 'joined') {
			this.map = null;
			return fm.page(null, fm.joinFirst(mode));
		}

		this.routeBox = el('div', { 'class': 'flowmesh-routes' });
		this.offerBox = el('div');
		this.exitStateBox = el('div');
		this.dnsBox = el('div');
		this.exitNote = el('div', { 'class': 'cbi-value-description flowmesh-pending' });
		this.useNote = el('div', { 'class': 'cbi-value-description flowmesh-pending' });

		m = new form.Map('flowmesh');
		this.map = m;

		/* shared networks */
		s = m.section(form.NamedSection, 'main', 'flowmesh', _('Shared networks'), _('Let other devices in the mesh reach networks behind this router. A mesh administrator approves each network in the console.'));
		s.addremove = false;

		o = s.option(form.Flag, 'advertise_lan', _('Share networks'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'lan_routes', _('Networks'), _('IPv4 or IPv6 networks, such as 192.168.1.0/24. Starts with this router\'s LAN networks.'));
		o.depends('advertise_lan', '1');
		o.datatype = 'string';
		// Nothing listed means "the LAN's networks": show those, so that there is nothing to
		// explain, and write the list only once it differs from them.
		o.cfgvalue = function(sid) {
			var listed = L.toArray(uci.get('flowmesh', sid, 'lan_routes'));

			return listed.length ? listed : fm.autoRoutes(self.lan);
		};
		o.validate = function(sid, value) {
			return (value == null || value === '') ? true : routeError(value);
		};
		// (The entry box refuses an invalid network as it is typed; one that got into the list some
		// other way, e.g. pasted and added with the button, still stops the save.)
		o.isValid = function(sid) {
			var w = this.getUIElement(sid);

			return (!w || w.isValid()) && L.toArray(w ? w.getValue() : []).every(function(v) { return routeError(v) === true; });
		};
		o.write = function(sid, value) {
			var list = [];

			L.toArray(value).forEach(function(v) {
				var r = fmstate.validateRoute(v);

				if (r.ok && list.indexOf(r.prefix) < 0)
					list.push(r.prefix);
			});

			// (the LAN's own networks again: back to following the LAN)
			if (sameSet(list, fm.autoRoutes(self.lan))) {
				if (L.toArray(uci.get('flowmesh', sid, 'lan_routes')).length)
					uci.unset('flowmesh', sid, 'lan_routes');
				return;
			}

			if (list.length)
				uci.set('flowmesh', sid, 'lan_routes', list);
			else
				uci.unset('flowmesh', sid, 'lan_routes');
		};

		// Hidden (sharing off), the list stays as it is: switching sharing back on brings the same
		// networks back. (form's `retain` does this from LuCI 22.03 on; 21.02 does not have it.)
		o.remove = function(sid) {
			if (this.isActive(sid))
				uci.unset('flowmesh', sid, 'lan_routes');
		};

		o = s.option(form.DummyValue, '_routes', _('Current state'));
		o.depends('advertise_lan', '1');
		o.renderWidget = function() { return self.routeBox; };

		/* exit node */
		s = m.section(form.NamedSection, 'main', 'flowmesh', _('Exit node'), _('An exit node carries Internet traffic for other devices. This router can be one, or send its LAN\'s Internet traffic through one, but not both at once.'));
		s.addremove = false;

		o = s.option(form.Flag, 'exit_node', _('Act as exit node'), _('Other devices may send their Internet traffic through this router. A mesh administrator approves it in the console.'));
		o.rmempty = false;

		o = s.option(form.DummyValue, '_offer', _('Current state'));
		o.depends('exit_node', '1');
		o.renderWidget = function() { return self.offerBox; };

		o = s.option(form.ListValue, 'use_exit_node', _('Use exit node'), _('Send the Internet traffic of every LAN device through this mesh device. The router\'s own traffic keeps using the local Internet connection, and the LAN\'s IPv6 Internet access is blocked meanwhile.'));
		o.value('', _('Don\'t use'));
		fmstate.exitOptions(this.status).forEach(function(opt) {
			o.value(opt.ip, (opt.online ? _('%s (%s)') : _('%s (%s, offline)')).format(opt.name, opt.ip));
		});
		var chosen = uci.get('flowmesh', 'main', 'use_exit_node');
		if (chosen && !fmstate.exitOptions(this.status).some(function(opt) { return opt.ip == chosen; }))
			o.value(chosen, _('%s (not available in the mesh)').format(chosen));

		o = s.option(form.DummyValue, '_exit_state', _('Current state'));
		o.renderWidget = function() { return self.exitStateBox; };

		o = s.option(form.Flag, 'kill_switch', _('Kill Switch'), _('While the exit node is offline, the LAN has no Internet access. Off: the LAN uses the local Internet connection until the exit node is back.'));
		o.default = '1';
		o.rmempty = false;

		/* name resolution */
		s = m.section(form.NamedSection, 'main', 'flowmesh', _('Name resolution'), _('Lets devices on the LAN reach mesh devices by name. Only mesh names are answered by FlowMesh; every other lookup works as before.'));
		s.addremove = false;

		o = s.option(form.Flag, 'lan_dns', _('Mesh names for the LAN'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.DummyValue, '_dns', _('Example'));
		o.depends('lan_dns', '1');
		o.renderWidget = function() { return self.dnsBox; };

		/* advanced */
		s = m.section(form.NamedSection, 'main', 'flowmesh', _('Advanced'));
		s.addremove = false;

		o = s.option(form.Flag, 'accept_routes', _('Use networks shared by other devices'), _('Reach the LANs other mesh devices share.'));
		o.rmempty = false;

		return m.render().then(function(node) {
			self.mapNode = node;
			node.addEventListener('widget-change', function() { self.syncExit(false); });
			node.addEventListener('cbi-dynlist-change', function() { self.markRoutes(); });
			self.decorate();
			self.refresh();

			poll.add(function() {
				return Promise.all([ helper([ 'status' ]), helper([ 'exitstate' ]) ]).then(function(r) {
					self.status = r[0];
					self.exitState = r[1];
					self.sum = fmstate.summarize(r[0]);
					self.refresh();
				});
			}, 5);

			return fm.page(null, node);
		});
	},

	widget: function(name) {
		var found = this.map.lookupOption(name, 'main');

		return found ? found[0].getUIElement(found[1]) : null;
	},

	// After every (re-)render of the form: the explanations next to the two exit node controls.
	decorate: function() {
		var exitW = this.widget('exit_node'), useW = this.widget('use_exit_node');

		[ [ exitW, this.exitNote ], [ useW, this.useNote ] ].forEach(function(p) {
			var field = p[0] && p[0].node && p[0].node.closest ? p[0].node.closest('.cbi-value-field') : null;

			if (field)
				field.appendChild(p[1]);
		});

		this.syncExit(true);
		this.markRoutes();
	},

	// Networks in the list that cannot be shared: shown in red, the reason as their tooltip.
	markRoutes: function() {
		var w = this.widget('lan_routes');

		if (!w || !w.node)
			return;

		Array.prototype.forEach.call(w.node.querySelectorAll('.item'), function(item) {
			var input = item.querySelector('input[type="hidden"]'), err = input ? routeError(input.value) : true;

			item.classList.toggle('flowmesh-bad', err !== true);
			item.setAttribute('title', err === true ? '' : err);
		});
	},

	// "Act as exit node" and "Use exit node" exclude each other: while one is set the other is
	// disabled, with the reason next to it. The Kill Switch only matters while using one.
	syncExit: function(initial) {
		var exitW = this.widget('exit_node'), useW = this.widget('use_exit_node'), killW = this.widget('kill_switch');

		if (!exitW || !useW)
			return;

		var acting = exitW.getValue() == '1', use = useW.getValue() || '';

		// (a hand-edited config may have both: offering wins, as in the service)
		if (acting && use != '') {
			useW.setValue('');
			use = '';
		}

		setDisabled(useW, acting);
		setDisabled(exitW, use != '');
		setDisabled(killW, use == '');

		setContent(this.useNote, acting ? _('Not available while this router acts as an exit node.') : '');
		setContent(this.exitNote, use != '' ? _('Not available while this router uses an exit node. Choose "Don\'t use" first.') : '');
	},

	// What is applied (the states below are about that, not about unsaved edits in the form, which
	// LuCI keeps in the same uci cache).
	snapshot: function() {
		var saved = {};

		[ 'advertise_lan', 'lan_routes', 'exit_node', 'use_exit_node' ].forEach(function(k) {
			saved[k] = uci.get('flowmesh', 'main', k);
		});

		this.saved = saved;
	},

	// The live parts: approval states, the exit node state, the name example.
	refresh: function() {
		var sum = this.sum, online = sum.state == 'running';

		/* shared networks, as saved */
		var wanted = fm.wantedRoutes(this.saved.lan_routes, this.lan), routes = [];

		if (this.saved.advertise_lan != '1') {
			routes.push(el('div', { 'class': 'flowmesh-muted' }, _('Not shared yet: save to start sharing.')));
		}
		else {
			if (!wanted.length)
				routes.push(el('div', {}, _('No LAN network found to share.')));

			var pending = false;

			fmstate.routeState(wanted, sum.primaryRoutes).forEach(function(r) {
				pending = pending || r.state == 'pending';
				routes.push(el('div', {}, [ el('code', {}, r.prefix), ' ', fm.approvalLabel(online, r.state == 'active') ]));
			});

			if (pending && online)
				routes.push(el('div', {}, fm.consoleLink()));
		}

		fmstate.conflicts(wanted, sum.peers).forEach(function(c) {
			routes.push(el('div', { 'class': 'alert-message warning' },
				_('%s overlaps a network that %s already shares. Devices may not reach the right one; consider changing this router\'s LAN network.').format(c.prefix, c.peer)));
		});

		setContent(this.routeBox, routes);

		/* offering this router as an exit node */
		if (this.saved.exit_node == '1')
			setContent(this.offerBox, [ fm.approvalLabel(online, sum.exitNodeOption), ' ', online && !sum.exitNodeOption ? fm.consoleLink() : '' ]);
		else
			setContent(this.offerBox, el('span', { 'class': 'flowmesh-muted' }, _('Not offered yet: save to offer it.')));

		/* using one */
		var want = this.saved.use_exit_node, es = this.exitState;
		var state = !want ? 'none' : ((es && es.want == want) ? es.state : 'unknown');

		setContent(this.exitStateBox, el('span', { 'class': fm.exitStateClass(state) }, fm.exitStateText(state, fm.exitName(this.status, want))));

		/* a name to try: a DNS label the mesh answers for (HostName is free text) */
		var suffix = (this.status && typeof this.status.MagicDNSSuffix == 'string') ? this.status.MagicDNSSuffix : '';
		var example = fmstate.nameExample(sum, suffix);

		setContent(this.dnsBox, example
			? el('span', {}, [ el('code', {}, 'ping ' + example), el('div', { 'class': 'flowmesh-hint' }, _('Run this on a LAN device.')) ])
			: el('span', { 'class': 'flowmesh-muted' }, _('No mesh names yet.')));
	},

	// form.Map.save stages the changes (and renders the form again from them); applyConfig then
	// commits them and runs `flowmesh-luci apply`.
	handleSaveApply: function(ev) {
		var self = this;

		if (!this.map)
			return Promise.resolve();

		fm.busy(_('Applying settings…'));

		return this.map.save(null, true).then(function() {
			self.decorate();
			return fm.applyConfig(null).then(function(ok) {
				ui.hideModal();
				if (ok)
					ui.addNotification(null, el('p', {}, _('Settings applied.')), 'info');
				self.snapshot();
			});
		}, function() {
			// (the form marks what is invalid)
			ui.hideModal();
			ui.addNotification(null, el('p', {}, _('Some settings are not valid; nothing was saved.')), 'warning');
		}).then(function() {
			// (LuCI's "unsaved changes" counter: the commit emptied it)
			if (ui.changes && ui.changes.init)
				L.resolveDefault(ui.changes.init());
			self.refresh();
		});
	},

	// (no Save & Apply / Reset while there is no form)
	addFooter: function() {
		return this.map ? this.super('addFooter', []) : el('div');
	},

	handleSave: null,

	handleReset: function() {
		var self = this;

		if (!this.map)
			return Promise.resolve();

		return this.map.reset().then(function() {
			self.decorate();
		});
	}
});
