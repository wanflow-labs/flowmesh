// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require poll';
'require uci';
'require ui';
'require network';
'require flowmesh.common as fm';
'require flowmesh.joincode as joincode';
'require flowmesh.state as fmstate';

// Services -> FlowMesh -> Overview: joining a mesh, or (once joined) the router's state in the mesh
// and the connect / disconnect / log out actions. The other pages: devices.js, settings.js,
// diagnostics.js, logs.js.

var el = fm.el, setContent = fm.setContent, helper = fm.helper;

// A name the helper accepts (letters, digits, hyphens; at most 63), from a system hostname.
function cleanHostname(name) {
	return String(name || '').replace(/[^A-Za-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
}

return view.extend({
	load: function() {
		return Promise.all([
			helper([ 'status' ]),
			helper([ 'exitstate' ]),
			uci.load('flowmesh'),
			L.resolveDefault(uci.load('system'), null),
			L.resolveDefault(network.getNetwork('lan'), null)
		]);
	},

	render: function(data) {
		this.lan = data[4];
		this.exitState = data[1];
		this.root = el('div');
		this.mode = null;
		this.update(data[0]);

		poll.add(L.bind(function() {
			return Promise.all([ helper([ 'status' ]), helper([ 'exitstate' ]) ]).then(L.bind(function(r) {
				this.exitState = r[1];
				this.update(r[0]);
			}, this));
		}, this), 5);

		return fm.page(_('Join this router to a Wanflow FlowMesh mesh network.'), this.root);
	},

	// A new status: switch views when the router joined or left, otherwise refresh in place (the
	// join form is left alone so typing is not interrupted).
	update: function(status) {
		var sum = fmstate.summarize(status);
		var mode = fm.modeOf(sum);

		this.status = status;
		this.sum = sum;

		if (mode == 'down')
			setContent(this.root, this.renderDown(status));
		else if (mode != this.mode)
			setContent(this.root, mode == 'join' ? this.renderJoin() : this.renderJoined());

		this.mode = mode;

		if (mode == 'joined')
			this.refreshJoined();
	},

	reloadStatus: function() {
		return Promise.all([ helper([ 'status' ]), helper([ 'exitstate' ]) ]).then(L.bind(function(r) {
			this.exitState = r[1];
			this.update(r[0]);
		}, this));
	},

	/* --- service not running --- */

	renderDown: function(status) {
		var enabled = uci.get('flowmesh', 'main', 'enabled') != '0';
		var body = [
			el('p', {}, enabled ? _('The FlowMesh service is not running.') : _('FlowMesh is turned off.')),
			el('p', {}, el('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleStart')
			}, _('Start')))
		];

		if (status && status.ok === false && status.code != 'daemon_down' && status.detail)
			body.splice(1, 0, el('pre', { 'class': 'flowmesh-detail' }, status.detail));

		return el('div', { 'class': 'cbi-section' }, body);
	},

	handleStart: function() {
		return fm.applyConfig({ enabled: '1' }).then(function() {
			uci.unload('flowmesh');
			return uci.load('flowmesh');
		}).then(L.bind(this.reloadStatus, this));
	},

	/* --- not joined --- */

	renderJoin: function() {
		var name = uci.get('flowmesh', 'main', 'hostname') || uci.get('system', '@system[0]', 'hostname');

		this.codeInput = el('textarea', {
			'class': 'cbi-input-textarea',
			'rows': 3,
			'spellcheck': 'false',
			'autocomplete': 'off',
			'placeholder': _('wanflow://… or the Linux install command from the console')
		});
		this.nameInput = el('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'value': cleanHostname(name),
			'maxlength': 63
		});
		this.serverInput = el('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'spellcheck': 'false',
			'autocomplete': 'off',
			'placeholder': 'https://'
		});
		this.keyInput = el('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'spellcheck': 'false',
			'autocomplete': 'off'
		});
		this.joinError = el('div');

		return el([], [
			el('div', { 'class': 'cbi-section' }, el('div', { 'class': 'alert-message notice flowmesh-signup' }, [
				el('p', {}, _('No mesh yet? Wanflow FlowMesh Free is free forever.')),
				el('a', {
					'class': 'btn cbi-button cbi-button-positive',
					'href': fm.SIGNUP_URL,
					'target': '_blank',
					'rel': 'noopener'
				}, _('Sign up free'))
			])),
			el('div', { 'class': 'cbi-section' }, [
				el('h3', {}, _('Join a mesh')),
				el('p', {}, _('In the console, add a device to your mesh and copy its join code (or the Linux install command), then paste it here.')),
				el('div', { 'class': 'cbi-value' }, [
					el('label', { 'class': 'cbi-value-title' }, _('Join code')),
					el('div', { 'class': 'cbi-value-field' }, this.codeInput)
				]),
				el('div', { 'class': 'cbi-value' }, [
					el('label', { 'class': 'cbi-value-title' }, _('Device name')),
					el('div', { 'class': 'cbi-value-field' }, [
						this.nameInput,
						el('div', { 'class': 'cbi-value-description' }, _('How this router appears in the mesh.'))
					])
				]),
				el('details', {}, [
					el('summary', {}, _('Enter manually')),
					el('div', { 'class': 'cbi-value' }, [
						el('label', { 'class': 'cbi-value-title' }, _('Mesh address')),
						el('div', { 'class': 'cbi-value-field' }, this.serverInput)
					]),
					el('div', { 'class': 'cbi-value' }, [
						el('label', { 'class': 'cbi-value-title' }, _('Join key')),
						el('div', { 'class': 'cbi-value-field' }, [
							this.keyInput,
							el('div', { 'class': 'cbi-value-description' }, _('Used when the join code box is empty.'))
						])
					])
				]),
				this.joinError,
				el('div', { 'class': 'cbi-page-actions' }, el('button', {
					'class': 'btn cbi-button cbi-button-apply',
					'click': ui.createHandlerFn(this, 'handleJoin')
				}, _('Join')))
			])
		]);
	},

	// The server and key to join with: the join code box, or else the manual fields.
	joinTarget: function() {
		var code = this.codeInput.value;

		if (code.trim() == '' && (this.serverInput.value.trim() != '' || this.keyInput.value.trim() != '')) {
			var server = this.serverInput.value.trim(), key = this.keyInput.value.trim();

			if (!/^https?:\/\/\S+$/.test(server))
				return { ok: false, text: _('Enter the mesh address, starting with https:// or http://.') };
			if (key == '')
				return { ok: false, text: _('Enter the join key.') };

			return { ok: true, server: server, key: key };
		}

		var r = joincode.parse(code);

		if (r.ok)
			return r;

		if (r.error == 'empty')
			return { ok: false, text: _('Paste a join code first.') };
		if (r.error == 'version')
			return { ok: false, text: _('This join code is newer than this plugin. Please upgrade luci-app-flowmesh.') };

		return { ok: false, text: _('This is not a join code. Paste the join code or the Linux install command from the console.') };
	},

	handleJoin: function() {
		var target = this.joinTarget(), name = this.nameInput.value.trim();

		setContent(this.joinError, null);

		if (!target.ok) {
			setContent(this.joinError, el('div', { 'class': 'alert-message warning' }, target.text));
			return Promise.resolve();
		}

		if (!/^[A-Za-z0-9-]{1,63}$/.test(name)) {
			setContent(this.joinError, fm.errorBox({ code: 'invalid_arg', detail: 'hostname' }));
			return Promise.resolve();
		}

		fm.busy(_('Joining the mesh… This can take up to half a minute.'));

		return helper([ 'up', target.server, target.key, name ], true).then(L.bind(function(res) {
			ui.hideModal();

			if (res.ok) {
				this.codeInput.value = '';
				this.keyInput.value = '';
			}
			else {
				setContent(this.joinError, fm.errorBox(res, true));
			}

			// (up saved the device name to UCI)
			uci.unload('flowmesh');
			return uci.load('flowmesh');
		}, this)).then(L.bind(this.reloadStatus, this));
	},

	/* --- joined --- */

	renderJoined: function() {
		this.statusTable = el('table', { 'class': 'table' });
		this.actionsBox = el('div', { 'class': 'cbi-page-actions' });

		return el([], [
			el('div', { 'class': 'cbi-section' }, [ el('h3', {}, _('Status')), this.statusTable ]),
			this.actionsBox
		]);
	},

	refreshJoined: function() {
		if (this.mode != 'joined' || !this.statusTable)
			return;

		var sum = this.sum, online = sum.state == 'running';
		var stateText = {
			running: el('span', { 'class': 'flowmesh-active' }, _('Online')),
			starting: el('span', { 'class': 'flowmesh-pending' }, _('Connecting…')),
			stopped: el('span', { 'class': 'flowmesh-muted' }, _('Disconnected'))
		}[sum.state] || sum.state;
		var paths = { direct: 0, relay: 0, 'peer-relay': 0 }, onlinePeers = 0;

		sum.peers.forEach(function(p) {
			if (p.online)
				onlinePeers++;
			if (p.online && p.path in paths)
				paths[p.path]++;
		});

		var via = [];
		if (paths.direct)
			via.push(_('direct: %d').format(paths.direct));
		if (paths['peer-relay'])
			via.push(_('high-speed relay: %d').format(paths['peer-relay']));
		if (paths.relay)
			via.push(_('relay: %d').format(paths.relay));

		var devicesLink = el('a', { 'href': L.url('admin', 'services', 'flowmesh', 'devices') },
			_('%d of %d online').format(onlinePeers, sum.peers.length));

		var rows = [
			[ _('Status'), stateText ],
			[ _('Device name'), sum.name || '—' ],
			[ _('Mesh IP'), sum.ips.length ? sum.ips.join(', ') : '—' ],
			[ _('Other devices'), sum.peers.length ? devicesLink : _('No other devices yet.') ],
			[ _('Connections'), via.length ? via.join(' · ') : _('none active') ],
			[ _('Shared networks'), this.sharedSummary(online) ],
			[ _('Exit node'), this.exitSummary(online) ]
		];

		setContent(this.statusTable, rows.map(function(r) {
			return el('tr', { 'class': 'tr' }, [
				el('td', { 'class': 'td left', 'width': '33%' }, r[0]),
				el('td', { 'class': 'td left' }, r[1])
			]);
		}));

		/* actions: rebuilt only when they change, or a click landing during a refresh is lost */
		var running = sum.state != 'stopped';

		if (this.actionsBox.getAttribute('data-running') == String(running))
			return;

		this.actionsBox.setAttribute('data-running', String(running));
		setContent(this.actionsBox, [
			running
				? el('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, 'handleDown') }, _('Disconnect'))
				: el('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, 'handleReconnect') }, _('Reconnect')),
			' ',
			el('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': ui.createHandlerFn(this, 'handleLogout') }, _('Log out'))
		]);
	},

	// "Shared networks" row: each network this router shares and its approval state.
	sharedSummary: function(online) {
		if (uci.get('flowmesh', 'main', 'advertise_lan') != '1')
			return el('span', { 'class': 'flowmesh-muted' }, _('Not shared'));

		var wanted = fm.wantedRoutes(uci.get('flowmesh', 'main', 'lan_routes'), this.lan);

		if (!wanted.length)
			return _('No LAN network found to share.');

		return el('div', { 'class': 'flowmesh-routes' }, fmstate.routeState(wanted, this.sum.primaryRoutes).map(function(r) {
			return el('div', {}, [ el('code', {}, r.prefix), ' ', fm.approvalLabel(online, r.state == 'active') ]);
		}));
	},

	// "Exit node" row: what this router does with exit nodes (offers itself, or uses one).
	exitSummary: function(online) {
		if (uci.get('flowmesh', 'main', 'exit_node') == '1')
			return el('span', {}, [ _('Offered to other devices'), ' — ', fm.approvalLabel(online, this.sum.exitNodeOption) ]);

		var want = uci.get('flowmesh', 'main', 'use_exit_node');
		var es = this.exitState;

		if (!want)
			return el('span', { 'class': 'flowmesh-muted' }, _('Not used'));

		// The watcher's state is for what it last saw configured: until it catches up, say so.
		var state = (es && es.want == want) ? es.state : 'unknown';

		return el('span', { 'class': fm.exitStateClass(state) }, fm.exitStateText(state, fm.exitName(this.status, want)));
	},

	runAction: function(args, text) {
		fm.busy(text);

		return helper(args, true).then(L.bind(function(res) {
			ui.hideModal();

			if (!res.ok)
				fm.notifyError(res);

			return this.reloadStatus();
		}, this));
	},

	handleDown: function() {
		return this.runAction([ 'down' ], _('Disconnecting…'));
	},

	handleReconnect: function() {
		return this.runAction([ 'reconnect' ], _('Reconnecting…'));
	},

	handleLogout: function() {
		ui.showModal(_('Log out of the mesh?'), [
			el('p', {}, _('This router leaves the mesh. Joining again needs a new join code from the console.')),
			el('div', { 'class': 'right' }, [
				el('button', { 'class': 'btn', 'click': function() { ui.hideModal(); } }, _('Cancel')),
				' ',
				el('button', {
					'class': 'btn cbi-button-negative',
					'click': L.bind(function() {
						this.runAction([ 'logout' ], _('Logging out…'));
					}, this)
				}, _('Log out'))
			])
		]);

		return Promise.resolve();
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
