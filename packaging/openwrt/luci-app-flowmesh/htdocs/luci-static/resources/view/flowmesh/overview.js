// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require dom';
'require poll';
'require rpc';
'require uci';
'require ui';
'require network';
'require flowmesh.joincode as joincode';
'require flowmesh.state as fmstate';

// Services -> FlowMesh. Everything goes through /usr/libexec/flowmesh-luci (rpcd `file exec`, see
// the luci-app-flowmesh ACL); settings are written to /etc/config/flowmesh and pushed with `apply`.

var HELPER = '/usr/libexec/flowmesh-luci';
var SIGNUP_URL = 'https://www.wanflow.com';
var CONSOLE_URL = 'https://console.wanflow.com';
// `up` waits up to 20 s for the node to come up and is stopped at 25 s: well above LuCI's default
// 20 s request timeout.
var LONG_TIMEOUT = 60;

var callExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ]
});

// The same call sent on its own (a batched request takes the first call's timeout).
var callExecAlone = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ],
	nobatch: true
});

var callUciSet = rpc.declare({
	object: 'uci',
	method: 'set',
	params: [ 'config', 'section', 'values' ],
	reject: true
});

// (LuCI's own pages stage changes and apply them with rollback; these toggles take effect at once,
// so they commit directly: the luci-app-flowmesh ACL grants commit and revert, for flowmesh only.)
var callUciCommit = rpc.declare({
	object: 'uci',
	method: 'commit',
	params: [ 'config' ],
	reject: true
});

var callUciRevert = rpc.declare({
	object: 'uci',
	method: 'revert',
	params: [ 'config' ]
});

// Run the helper; resolves to its JSON answer, or {ok:false, code, detail} when there is none.
function helper(args, long) {
	var p;

	if (long) {
		// rpc reads the timeout when the request is made: raise it for this one call only.
		var saved = L.env.rpctimeout;

		L.env.rpctimeout = LONG_TIMEOUT;
		try {
			p = callExecAlone(HELPER, args);
		}
		finally {
			L.env.rpctimeout = saved;
		}
	}
	else {
		p = callExec(HELPER, args);
	}

	return Promise.resolve(p).then(function(res) {
		if (res == null || typeof res != 'object')
			return { ok: false, code: 'rpc', detail: rpc.getStatusText(res) };

		try {
			return JSON.parse(res.stdout);
		}
		catch (e) {
			return { ok: false, code: 'unknown', detail: String(res.stdout || res.stderr || '') };
		}
	}, function(err) {
		return { ok: false, code: 'rpc', detail: String(err && err.message || err) };
	});
}

function consoleLink() {
	return E('a', { href: CONSOLE_URL, target: '_blank', rel: 'noopener' }, _('Open the console'));
}

// The user-facing text for a helper error code.
function errorText(res) {
	switch (res.code) {
	case 'key_invalid':
		return _('This join code has expired or was already used. Generate a new one in the console.');
	case 'site_limit':
		return _('Your mesh has reached its site limit.');
	case 'unreachable':
		return _('Cannot reach the mesh server. Check the address and this router\'s Internet connection.');
	case 'timeout':
		return _('The mesh server did not answer in time. Please try again.');
	case 'daemon_down':
		return _('The FlowMesh service is not running.');
	case 'invalid_arg':
		if (res.detail == 'hostname')
			return _('The device name may only contain letters, digits and hyphens (at most 63).');
		if (res.detail == 'auth_key')
			return _('The join key is not valid.');
		if (res.detail == 'server_url')
			return _('The mesh address is not valid.');
		return _('Invalid request.');
	case 'rpc':
		return _('The router did not answer: %s').format(res.detail || '?');
	default:
		return _('The operation failed.');
	}
}

// An alert box for a failed helper call: the text, the server's own words where they matter, and a
// console link where the fix is made there.
function errorBox(res) {
	var body = [ E('p', {}, errorText(res)) ];

	if ((res.code == 'site_limit' || res.code == 'unknown') && res.detail)
		body.push(E('pre', { 'class': 'flowmesh-detail' }, res.detail));

	if (res.code == 'key_invalid' || res.code == 'site_limit')
		body.push(E('p', {}, consoleLink()));

	return E('div', { 'class': 'alert-message warning' }, body);
}

function notifyError(res) {
	ui.addNotification(null, Array.prototype.slice.call(errorBox(res).childNodes), 'danger');
}

// A name the helper accepts (letters, digits, hyphens; at most 63), from a system hostname.
function cleanHostname(name) {
	return String(name || '').replace(/[^A-Za-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
}

function busy(text) {
	ui.showModal(null, [ E('p', { 'class': 'spinning' }, text) ]);
}

return view.extend({
	load: function() {
		return Promise.all([
			helper([ 'status' ]),
			uci.load('flowmesh'),
			L.resolveDefault(uci.load('system'), null),
			L.resolveDefault(network.getNetwork('lan'), null)
		]);
	},

	render: function(data) {
		this.lan = data[3];
		this.root = E('div', { 'class': 'flowmesh' });
		this.mode = null;
		this.update(data[0]);

		poll.add(L.bind(function() {
			return helper([ 'status' ]).then(L.bind(this.update, this));
		}, this), 5);

		return E([], [
			E('style', {}, [
				'.flowmesh .flowmesh-pending { color: #b8860b; }',
				'.flowmesh .flowmesh-active { color: #3c763d; }',
				'.flowmesh .flowmesh-muted { opacity: .7; }',
				'.flowmesh .flowmesh-detail { white-space: pre-wrap; word-break: break-word; }',
				'.flowmesh .flowmesh-log { max-height: 30em; overflow: auto; white-space: pre-wrap; font-size: 90%; }',
				'.flowmesh .flowmesh-signup { display: flex; flex-wrap: wrap; align-items: center; gap: .5em 1em; }',
				'.flowmesh .flowmesh-signup p { margin: 0; }',
				'.flowmesh textarea { width: 100%; }',
				'.flowmesh label.flowmesh-check { display: block; margin: .3em 0; }',
				'.flowmesh .flowmesh-sub { margin: .2em 0 .8em 1.8em; }'
			].join('\n')),
			E('h2', {}, _('FlowMesh')),
			E('div', { 'class': 'cbi-map-descr' }, _('Join this router to a Wanflow FlowMesh mesh network.')),
			this.root
		]);
	},

	// A new status: switch views when the router joined or left, otherwise refresh in place (the
	// join form is left alone so typing is not interrupted).
	update: function(status) {
		var sum = fmstate.summarize(status);
		var mode = sum.state == 'down' ? 'down' : (fmstate.joined(sum) ? 'joined' : 'join');

		this.status = status;
		this.sum = sum;

		if (mode == 'down')
			dom.content(this.root, this.renderDown(status));
		else if (mode != this.mode)
			dom.content(this.root, mode == 'join' ? this.renderJoin() : this.renderJoined());

		this.mode = mode;

		if (mode == 'joined')
			this.refreshJoined();
	},

	reloadStatus: function() {
		return helper([ 'status' ]).then(L.bind(this.update, this));
	},

	/* --- service not running --- */

	renderDown: function(status) {
		var enabled = uci.get('flowmesh', 'main', 'enabled') != '0';
		var body = [
			E('p', {}, enabled ? _('The FlowMesh service is not running.') : _('FlowMesh is turned off.')),
			E('p', {}, E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleStart')
			}, _('Start')))
		];

		if (status && status.ok === false && status.code != 'daemon_down' && status.detail)
			body.splice(1, 0, E('pre', { 'class': 'flowmesh-detail' }, status.detail));

		return E('div', { 'class': 'cbi-section' }, body);
	},

	handleStart: function() {
		return this.setOptions({ enabled: '1' }).then(L.bind(this.reloadStatus, this));
	},

	/* --- not joined --- */

	renderJoin: function() {
		var name = uci.get('flowmesh', 'main', 'hostname') || uci.get('system', '@system[0]', 'hostname');

		this.codeInput = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': 3,
			'spellcheck': 'false',
			'autocomplete': 'off',
			'placeholder': _('wanflow://… or the Linux install command from the console')
		});
		this.nameInput = E('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'value': cleanHostname(name),
			'maxlength': 63
		});
		this.serverInput = E('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'spellcheck': 'false',
			'autocomplete': 'off',
			'placeholder': 'https://'
		});
		this.keyInput = E('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'spellcheck': 'false',
			'autocomplete': 'off'
		});
		this.joinError = E('div');

		return E([], [
			E('div', { 'class': 'cbi-section' }, E('div', { 'class': 'alert-message notice flowmesh-signup' }, [
				E('p', {}, _('No mesh yet? Wanflow FlowMesh Free is free forever.')),
				E('a', {
					'class': 'btn cbi-button cbi-button-positive',
					'href': SIGNUP_URL,
					'target': '_blank',
					'rel': 'noopener'
				}, _('Sign up free'))
			])),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Join a mesh')),
				E('p', {}, _('In the console, add a device to your mesh and copy its join code (or the Linux install command), then paste it here.')),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Join code')),
					E('div', { 'class': 'cbi-value-field' }, this.codeInput)
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Device name')),
					E('div', { 'class': 'cbi-value-field' }, [
						this.nameInput,
						E('div', { 'class': 'cbi-value-description' }, _('How this router appears in the mesh.'))
					])
				]),
				E('details', {}, [
					E('summary', {}, _('Enter manually')),
					E('div', { 'class': 'cbi-value' }, [
						E('label', { 'class': 'cbi-value-title' }, _('Mesh address')),
						E('div', { 'class': 'cbi-value-field' }, this.serverInput)
					]),
					E('div', { 'class': 'cbi-value' }, [
						E('label', { 'class': 'cbi-value-title' }, _('Join key')),
						E('div', { 'class': 'cbi-value-field' }, [
							this.keyInput,
							E('div', { 'class': 'cbi-value-description' }, _('Used when the join code box is empty.'))
						])
					])
				]),
				this.joinError,
				E('div', { 'class': 'cbi-page-actions' }, E('button', {
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

		dom.content(this.joinError, null);

		if (!target.ok) {
			dom.content(this.joinError, E('div', { 'class': 'alert-message warning' }, target.text));
			return Promise.resolve();
		}

		if (!/^[A-Za-z0-9-]{1,63}$/.test(name)) {
			dom.content(this.joinError, errorBox({ code: 'invalid_arg', detail: 'hostname' }));
			return Promise.resolve();
		}

		busy(_('Joining the mesh… This can take up to half a minute.'));

		return helper([ 'up', target.server, target.key, name ], true).then(L.bind(function(res) {
			ui.hideModal();

			if (res.ok) {
				this.codeInput.value = '';
				this.keyInput.value = '';
			}
			else {
				dom.content(this.joinError, errorBox(res));
			}

			// (up saved the device name to UCI)
			uci.unload('flowmesh');
			return uci.load('flowmesh');
		}, this)).then(L.bind(this.reloadStatus, this));
	},

	/* --- joined --- */

	renderJoined: function() {
		var self = this;

		function check(option, label, description) {
			var input = E('input', { 'type': 'checkbox' });

			input.checked = uci.get('flowmesh', 'main', option) == '1';
			input.addEventListener('change', function() {
				var values = {};

				values[option] = input.checked ? '1' : '0';
				input.disabled = true;
				self.setOptions(values).finally(function() {
					input.checked = uci.get('flowmesh', 'main', option) == '1';
					input.disabled = false;
					self.refreshJoined();
				});
			});

			return E('div', {}, [
				E('label', { 'class': 'flowmesh-check' }, [ input, ' ', label ]),
				description ? E('div', { 'class': 'cbi-value-description flowmesh-sub' }, description) : ''
			]);
		}

		this.statusTable = E('table', { 'class': 'table' });
		this.routesBox = E('div', { 'class': 'flowmesh-sub' });
		this.exitBox = E('div', { 'class': 'flowmesh-sub' });
		this.peersBox = E('div');
		this.actionsBox = E('div', { 'class': 'cbi-page-actions' });
		this.logBox = E('pre', { 'class': 'flowmesh-log' }, _('Loading…'));

		var logs = E('details', {}, [
			E('summary', {}, _('Logs')),
			E('p', {}, E('button', {
				'class': 'btn cbi-button',
				'click': ui.createHandlerFn(this, 'loadLogs')
			}, _('Refresh'))),
			this.logBox
		]);

		logs.addEventListener('toggle', function() {
			if (logs.open)
				self.loadLogs();
		});

		return E([], [
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Status')), this.statusTable ]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Settings')),
				check('advertise_lan', _('Share local LAN'), _('Lets other devices in the mesh reach this router\'s LAN. A mesh administrator approves it in the console.')),
				this.routesBox,
				check('exit_node', _('Act as exit node'), _('Other devices may send their Internet traffic through this router. A mesh administrator approves it in the console.')),
				this.exitBox,
				check('accept_routes', _('Use networks shared by other devices'), _('Reach the LANs other mesh devices share.'))
			]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Devices in this mesh')), this.peersBox ]),
			this.actionsBox,
			E('div', { 'class': 'cbi-section' }, logs)
		]);
	},

	// The networks this router shares when "Share local LAN" is on: the listed ones, or the LAN's.
	wantedRoutes: function() {
		var listed = L.toArray(uci.get('flowmesh', 'main', 'lan_routes'));

		if (listed.length)
			return listed;

		var addrs = (this.lan && this.lan.getIPAddrs) ? this.lan.getIPAddrs() : [];

		return addrs.map(fmstate.network).filter(function(n, i, all) {
			return n != null && all.indexOf(n) == i;
		});
	},

	refreshJoined: function() {
		if (this.mode != 'joined' || !this.statusTable)
			return;

		var sum = this.sum;
		var stateText = {
			running: _('Online'),
			starting: _('Connecting…'),
			stopped: _('Disconnected')
		}[sum.state] || sum.state;
		var paths = { direct: 0, relay: 0, 'peer-relay': 0 };

		sum.peers.forEach(function(p) {
			if (p.path in paths)
				paths[p.path]++;
		});

		var via = [];
		if (paths.direct)
			via.push(_('direct: %d').format(paths.direct));
		if (paths['peer-relay'])
			via.push(_('high-speed relay: %d').format(paths['peer-relay']));
		if (paths.relay)
			via.push(_('relay: %d').format(paths.relay));

		var rows = [
			[ _('Status'), stateText ],
			[ _('Mesh IP'), sum.ips.length ? sum.ips.join(', ') : '—' ],
			[ _('Device name'), sum.name || '—' ],
			[ _('Connections'), via.length ? via.join(' · ') : _('none active') ]
		];

		dom.content(this.statusTable, rows.map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
				E('td', { 'class': 'td left' }, r[1])
			]);
		}));

		/* shared networks and exit node: approval states only mean something while connected */
		var online = sum.state == 'running';
		var label = function(active) {
			if (!online)
				return E('span', { 'class': 'flowmesh-muted' }, _('Not shared while disconnected'));

			return active
				? E('span', { 'class': 'flowmesh-active' }, _('Active'))
				: E('span', { 'class': 'flowmesh-pending' }, _('Advertised — waiting for an admin to approve it in the console'));
		};
		var routes = [];

		if (uci.get('flowmesh', 'main', 'advertise_lan') == '1') {
			var wanted = this.wantedRoutes(), states = fmstate.routeState(wanted, sum.primaryRoutes);
			var pending = false;

			if (!wanted.length)
				routes.push(E('p', {}, _('No LAN network found to share.')));

			states.forEach(function(r) {
				pending = pending || r.state == 'pending';
				routes.push(E('div', {}, [ E('code', {}, r.prefix), ' ', label(r.state == 'active') ]));
			});

			if (pending && online)
				routes.push(E('p', {}, consoleLink()));

			fmstate.conflicts(wanted, sum.peers).forEach(function(c) {
				routes.push(E('div', { 'class': 'alert-message warning' },
					_('%s overlaps a network that %s already shares. Devices may not reach the right one; consider changing this router\'s LAN network.').format(c.prefix, c.peer)));
			});
		}

		dom.content(this.routesBox, routes);

		/* exit node */
		var exit = [];

		if (uci.get('flowmesh', 'main', 'exit_node') == '1') {
			exit.push(label(sum.exitNodeOption));

			if (online && !sum.exitNodeOption)
				exit.push(' ', consoleLink());
		}

		dom.content(this.exitBox, exit);

		/* peers */
		var pathText = {
			direct: _('Direct'),
			relay: _('Relay'),
			'peer-relay': _('High-speed relay'),
			idle: _('Idle')
		};

		if (!sum.peers.length) {
			dom.content(this.peersBox, E('p', {}, _('No other devices yet.')));
		}
		else {
			dom.content(this.peersBox, E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, _('Name')),
					E('th', { 'class': 'th' }, _('Mesh IP')),
					E('th', { 'class': 'th' }, _('Status')),
					E('th', { 'class': 'th' }, _('Connection'))
				])
			].concat(sum.peers.map(function(p) {
				return E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td' }, p.name),
					E('td', { 'class': 'td' }, p.ips.join(', ')),
					E('td', { 'class': 'td' }, p.online ? _('Online') : _('Offline')),
					E('td', { 'class': 'td' }, p.online ? pathText[p.path] : '—')
				]);
			}))));
		}

		/* actions: rebuilt only when they change, or a click landing during a refresh is lost */
		var running = sum.state != 'stopped';

		if (this.actionsBox.getAttribute('data-running') == String(running))
			return;

		this.actionsBox.setAttribute('data-running', String(running));
		dom.content(this.actionsBox, [
			running
				? E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, 'handleDown') }, _('Disconnect'))
				: E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, 'handleReconnect') }, _('Reconnect')),
			' ',
			E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': ui.createHandlerFn(this, 'handleLogout') }, _('Log out'))
		]);
	},

	loadLogs: function() {
		return helper([ 'logs' ]).then(L.bind(function(res) {
			var lines = (res.ok && Array.isArray(res.lines)) ? res.lines : null;

			dom.content(this.logBox, lines ? (lines.length ? lines.join('\n') : _('No log lines.')) : errorText(res));

			if (lines)
				this.logBox.scrollTop = this.logBox.scrollHeight;
		}, this));
	},

	// Write options to /etc/config/flowmesh and push them to the daemon.
	setOptions: function(values) {
		return callUciSet('flowmesh', 'main', values).then(function() {
			return callUciCommit('flowmesh');
		}).then(function() {
			return helper([ 'apply' ], true);
		}).then(function(res) {
			if (!res.ok)
				notifyError(res);
		}, function(err) {
			// Not written: drop the staged change too, or the page would show it as set.
			notifyError({ code: 'rpc', detail: String(err && err.message || err) });
			return L.resolveDefault(callUciRevert('flowmesh'));
		}).then(function() {
			uci.unload('flowmesh');
			return uci.load('flowmesh');
		});
	},

	runAction: function(args, text) {
		busy(text);

		return helper(args, true).then(L.bind(function(res) {
			ui.hideModal();

			if (!res.ok)
				notifyError(res);

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
			E('p', {}, _('This router leaves the mesh. Joining again needs a new join code from the console.')),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': function() { ui.hideModal(); } }, _('Cancel')),
				' ',
				E('button', {
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
