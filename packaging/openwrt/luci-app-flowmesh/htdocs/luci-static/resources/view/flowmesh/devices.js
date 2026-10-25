// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require poll';
'require ui';
'require flowmesh.common as fm';
'require flowmesh.state as fmstate';

// Services -> FlowMesh -> Devices: the devices in the mesh, how this router reaches each, traffic,
// an on-demand latency test, exit node marks and the networks each one shares.

var el = fm.el, setContent = fm.setContent, helper = fm.helper;

function tag(text, cls) {
	return el('span', { 'class': 'flowmesh-tag' + (cls ? ' ' + cls : '') }, text);
}

function pathText(path) {
	return {
		direct: _('Direct'),
		relay: _('Relay'),
		'peer-relay': _('High-speed relay'),
		idle: _('Idle')
	}[path] || _('Unknown');
}

function routesCell(routes) {
	// (an exit node's default routes are shown as its "Exit node" mark instead)
	routes = routes.filter(function(r) { return r != '0.0.0.0/0' && r != '::/0'; });

	return routes.length ? el('div', { 'class': 'flowmesh-routes' }, routes.map(function(r) { return el('div', {}, el('code', {}, r)); })) : '—';
}

return view.extend({
	load: function() {
		return helper([ 'status' ]);
	},

	render: function(status) {
		this.rows = {};          // mesh IP -> {tr, cells, button}
		this.latency = {};       // mesh IP -> ping result, or 'busy'
		this.body = el('div');
		this.update(status);

		poll.add(L.bind(function() {
			return helper([ 'status' ]).then(L.bind(this.update, this));
		}, this), 5);

		return fm.page(_('The devices in this mesh and how this router reaches them.'), this.body);
	},

	update: function(status) {
		var sum = fmstate.summarize(status), mode = fm.modeOf(sum);

		if (mode != 'joined') {
			if (this.mode != mode)
				setContent(this.body, fm.joinFirst(mode));
			this.mode = mode;
			this.table = null;
			return;
		}

		if (this.mode != 'joined' || !this.table) {
			this.rows = {};
			this.table = el('table', { 'class': 'table' }, el('tr', { 'class': 'tr table-titles' }, [
				el('th', { 'class': 'th' }, _('Name')),
				el('th', { 'class': 'th' }, _('Mesh IP')),
				el('th', { 'class': 'th' }, _('Status')),
				el('th', { 'class': 'th' }, _('Connection')),
				el('th', { 'class': 'th' }, _('Received / sent')),
				el('th', { 'class': 'th' }, _('Latency')),
				el('th', { 'class': 'th' }, _('Shared networks'))
			]));
			this.selfBox = el('div');
			this.empty = el('p', {}, _('No other devices yet.'));
			setContent(this.body, [
				el('div', { 'class': 'cbi-section' }, [ el('h3', {}, _('This router')), this.selfBox ]),
				el('div', { 'class': 'cbi-section' }, [
					el('h3', {}, _('Other devices')),
					this.table,
					this.empty,
					el('p', { 'class': 'flowmesh-hint' }, _('Traffic is counted since the current connection to each device was set up. Latency is measured only when you ask for it.'))
				])
			]);
		}

		this.mode = mode;
		this.renderSelf(sum);
		this.renderPeers(sum);
	},

	renderSelf: function(sum) {
		// (approved networks only: Settings shows what is still waiting for approval)
		setContent(this.selfBox, el('table', { 'class': 'table' }, [
			[ _('Device name'), sum.name || '—' ],
			[ _('Mesh IP'), sum.ips.length ? sum.ips.join(', ') : '—' ],
			[ _('Shared networks'), routesCell(sum.primaryRoutes) ],
			[ _('Exit node'), sum.exitNodeOption ? tag(_('Offered to other devices'), 'flowmesh-active') : '—' ]
		].map(function(r) {
			return el('tr', { 'class': 'tr' }, [
				el('td', { 'class': 'td left', 'width': '33%' }, r[0]),
				el('td', { 'class': 'td left' }, r[1])
			]);
		})));
	},

	// Rows are kept per device (by mesh IP) and only their cells refreshed: a latency button
	// clicked during a refresh still works, and a result stays until the device leaves.
	renderPeers: function(sum) {
		var seen = {}, self = this;

		this.empty.style.display = sum.peers.length ? 'none' : '';
		this.table.style.display = sum.peers.length ? '' : 'none';

		sum.peers.forEach(function(p) {
			var key = p.ips[0] || p.name, row = self.rows[key];

			seen[key] = true;

			if (!row) {
				row = { cells: [] };
				for (var i = 0; i < 7; i++)
					row.cells.push(el('td', { 'class': 'td' }));
				row.button = el('button', {
					'class': 'btn cbi-button',
					'click': ui.createHandlerFn(self, 'handlePing', key)
				}, _('Test'));
				row.result = el('span');
				setContent(row.cells[5], el('span', { 'class': 'flowmesh-nowrap' }, [ row.button, ' ', row.result ]));
				row.tr = el('tr', { 'class': 'tr' }, row.cells);
				self.rows[key] = row;
			}

			// (appended in name order: an existing row moves into place)
			self.table.appendChild(row.tr);

			var marks = [];
			if (p.exitNode)
				marks.push(tag(_('Current exit node'), 'flowmesh-active'));
			else if (p.exitNodeOption)
				marks.push(tag(_('Exit node')));

			setContent(row.cells[0], [ el('div', {}, p.name), el('div', {}, marks) ]);
			setContent(row.cells[1], p.ips.join(', ') || '—');
			setContent(row.cells[2], p.online
				? el('span', { 'class': 'flowmesh-active' }, _('Online'))
				: el('span', { 'class': 'flowmesh-muted' }, _('Offline')));
			setContent(row.cells[3], p.online ? pathText(p.path) : '—');
			setContent(row.cells[4], el('span', { 'class': 'flowmesh-nowrap' },
				'↓ %s / ↑ %s'.format(fmstate.formatBytes(p.rxBytes), fmstate.formatBytes(p.txBytes))));
			setContent(row.cells[6], routesCell(p.primaryRoutes));

			row.ip = p.ips[0];
			row.button.disabled = !row.ip || self.latency[key] == 'busy';
			self.showLatency(key);
		});

		for (var key in this.rows) {
			if (!seen[key]) {
				this.rows[key].tr.remove();
				delete this.rows[key];
				delete this.latency[key];
			}
		}
	},

	showLatency: function(key) {
		var row = this.rows[key], r = this.latency[key];

		if (!row)
			return;

		if (r == null)
			setContent(row.result, '');
		else if (r == 'busy')
			setContent(row.result, el('em', { 'class': 'spinning' }, _('Testing…')));
		else if (!r.ok)
			setContent(row.result, el('span', { 'class': 'flowmesh-bad', 'title': r.detail || '' }, fm.errorText(r)));
		else if (r.ms == null)
			setContent(row.result, el('span', { 'class': 'flowmesh-bad' }, _('No reply')));
		else
			setContent(row.result, el('span', {}, [
				_('%d ms').format(r.ms), ' ',
				el('span', { 'class': 'flowmesh-muted' }, '(%s)'.format(pathText(r.path == 'unknown' ? null : r.path)))
			]));
	},

	handlePing: function(key) {
		var row = this.rows[key];

		if (!row || !row.ip)
			return Promise.resolve();

		this.latency[key] = 'busy';
		row.button.disabled = true;
		this.showLatency(key);

		return helper([ 'ping', row.ip ], true).then(L.bind(function(res) {
			this.latency[key] = res;

			if (this.rows[key])
				this.rows[key].button.disabled = false;

			this.showLatency(key);
		}, this));
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
