// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require ui';
'require flowmesh.common as fm';
'require flowmesh.state as fmstate';

// Services -> FlowMesh -> Diagnostics: one-off checks run when asked (never in the background) -
// the network check, a ping to one device, and a diagnostic report to send to support. Their raw
// output is shown as it is.

var el = fm.el, setContent = fm.setContent, helper = fm.helper;

function table(rows) {
	return el('table', { 'class': 'table' }, rows.map(function(r) {
		return el('tr', { 'class': 'tr' }, [
			el('td', { 'class': 'td left', 'width': '33%' }, r[0]),
			el('td', { 'class': 'td left' }, r[1])
		]);
	}));
}

function yesNo(v, yes, no) {
	return v ? el('span', { 'class': 'flowmesh-active' }, yes) : el('span', { 'class': 'flowmesh-bad' }, no);
}

function pathText(path) {
	return {
		direct: _('Direct connection'),
		relay: _('Through a relay'),
		'peer-relay': _('Through a high-speed relay')
	}[path] || _('Unknown');
}

return view.extend({
	load: function() {
		return helper([ 'status' ]);
	},

	render: function(status) {
		var sum = fmstate.summarize(status), mode = fm.modeOf(sum);

		if (mode != 'joined')
			return fm.page(null, fm.joinFirst(mode));

		return fm.page(_('Checks to run when something does not work as expected. Each one runs once, when you click its button.'), [
			this.renderNetcheck(),
			this.renderPing(sum),
			this.renderReport()
		]);
	},

	/* network check */

	renderNetcheck: function() {
		this.netcheckBox = el('div');

		return el('div', { 'class': 'cbi-section' }, [
			el('h3', {}, _('Network check')),
			el('p', {}, _('Checks how this router\'s Internet connection suits the mesh: whether UDP gets through, how easily direct connections can be made, and the latency to each relay region. Takes up to 20 seconds.')),
			el('div', { 'class': 'flowmesh-bar' }, el('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleNetcheck')
			}, _('Run network check'))),
			this.netcheckBox
		]);
	},

	handleNetcheck: function() {
		setContent(this.netcheckBox, el('p', { 'class': 'spinning' }, _('Checking the network…')));

		return Promise.all([ helper([ 'netcheck' ], true), helper([ 'regions' ]) ]).then(L.bind(function(r) {
			var res = r[0];

			if (res == null || typeof res != 'object' || res.ok === false) {
				setContent(this.netcheckBox, fm.errorBox(res || {}));
				return;
			}

			var n = fmstate.netcheckSummary(res, fmstate.regionNames(r[1]));
			var punch = {
				easy: el('span', { 'class': 'flowmesh-active' }, _('Easy: direct connections usually work')),
				hard: el('span', { 'class': 'flowmesh-pending' }, _('Hard: this network\'s NAT changes ports per destination; connections may go through a relay')),
				unknown: el('span', { 'class': 'flowmesh-muted' }, _('Unknown (finding out needs answers from two or more relay servers)'))
			}[n.holePunch];
			var regionName = function(x) { return x ? '%s (%s)'.format(x.name, x.ms == null ? '—' : _('%s ms').format(x.ms)) : _('None'); };

			var body = [
				table([
					[ _('UDP'), yesNo(n.udp, _('Available'), _('Blocked: connections go through a relay')) ],
					[ _('Direct connections'), punch ],
					[ _('Public IPv4 address'), n.ipv4 || '—' ],
					[ _('Public IPv6 address'), n.ipv6 || '—' ],
					[ _('Nearest relay region'), regionName(n.preferred) ]
				])
			];

			if (n.regions.length) {
				body.push(el('h4', {}, _('Relay region latency')), el('table', { 'class': 'table' }, [
					el('tr', { 'class': 'tr table-titles' }, [
						el('th', { 'class': 'th' }, _('Region')),
						el('th', { 'class': 'th' }, _('Latency'))
					])
				].concat(n.regions.map(function(x) {
					var best = n.preferred && n.preferred.id == x.id;

					return el('tr', { 'class': 'tr' }, [
						el('td', { 'class': 'td' }, [ x.name, best ? ' ' : '', best ? el('span', { 'class': 'flowmesh-tag flowmesh-active' }, _('Nearest')) : '' ]),
						el('td', { 'class': 'td' }, _('%s ms').format(x.ms))
					]);
				}))));
			}
			else {
				body.push(el('p', { 'class': 'flowmesh-bad' }, _('No relay region answered.')));
			}

			setContent(this.netcheckBox, body);
		}, this));
	},

	/* ping */

	renderPing: function(sum) {
		var peers = sum.peers.filter(function(p) { return p.ips.length; });

		this.pingBox = el('div');
		this.pingSelect = el('select', { 'class': 'cbi-input-select' }, peers.map(function(p) {
			return el('option', { 'value': p.ips[0] }, [ '%s (%s)%s'.format(p.name, p.ips[0], p.online ? '' : ' — ' + _('offline')) ]);
		}));

		return el('div', { 'class': 'cbi-section' }, [
			el('h3', {}, _('Ping')),
			el('p', {}, _('Sends three pings to a device in the mesh and shows whether they go directly or through a relay. A ping also prompts the two devices to try a direct connection.')),
			peers.length ? el('div', { 'class': 'flowmesh-bar' }, [
				this.pingSelect,
				el('button', {
					'class': 'btn cbi-button cbi-button-action',
					'click': ui.createHandlerFn(this, 'handlePing')
				}, _('Ping'))
			]) : el('p', {}, _('No other devices yet.')),
			this.pingBox
		]);
	},

	handlePing: function() {
		var ip = this.pingSelect.value;

		if (!ip)
			return Promise.resolve();

		setContent(this.pingBox, el('p', { 'class': 'spinning' }, _('Pinging %s…').format(ip)));

		return helper([ 'ping', ip ], true).then(L.bind(function(res) {
			if (!res.ok) {
				setContent(this.pingBox, fm.errorBox(res));
				return;
			}

			var verdict = res.ms == null
				? el('p', { 'class': 'flowmesh-bad' }, _('No reply.'))
				: el('p', {}, [ el('strong', {}, _('%d ms').format(res.ms)), ' — ', pathText(res.path) ]);

			setContent(this.pingBox, [
				verdict,
				el('pre', { 'class': 'flowmesh-log' }, Array.isArray(res.lines) && res.lines.length ? res.lines.join('\n') : _('No output.'))
			]);
		}, this));
	},

	/* diagnostic report */

	renderReport: function() {
		this.reportBox = el('div');

		return el('div', { 'class': 'cbi-section' }, [
			el('h3', {}, _('Diagnostic report')),
			el('p', {}, _('Collects this router\'s FlowMesh state into a report you can copy and send to support. Nothing is sent automatically.')),
			el('div', { 'class': 'flowmesh-bar' }, el('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleReport')
			}, _('Generate report'))),
			this.reportBox
		]);
	},

	handleReport: function() {
		setContent(this.reportBox, el('p', { 'class': 'spinning' }, _('Generating the report…')));

		return helper([ 'bugreport' ], true).then(L.bind(function(res) {
			if (!res.ok || typeof res.text != 'string') {
				setContent(this.reportBox, fm.errorBox(res));
				return;
			}

			var area = el('textarea', { 'class': 'cbi-input-textarea', 'rows': 16, 'readonly': 'readonly', 'spellcheck': 'false', 'wrap': 'off' });
			var copied = el('span', { 'class': 'flowmesh-active' });

			area.value = res.text;

			setContent(this.reportBox, [
				el('div', { 'class': 'flowmesh-bar' }, [
					el('button', {
						'class': 'btn cbi-button cbi-button-positive',
						'click': function() {
							var done = function() { setContent(copied, _('Copied.')); };

							// (navigator.clipboard needs HTTPS; LuCI is often plain HTTP)
							if (navigator.clipboard && window.isSecureContext) {
								navigator.clipboard.writeText(area.value).then(done, function() {
									area.select();
									setContent(copied, _('Select the text and copy it with Ctrl+C.'));
								});
							}
							else {
								area.focus();
								area.select();
								try {
									if (document.execCommand('copy'))
										done();
									else
										setContent(copied, _('Select the text and copy it with Ctrl+C.'));
								}
								catch (e) {
									setContent(copied, _('Select the text and copy it with Ctrl+C.'));
								}
							}
						}
					}, _('Copy')),
					copied
				]),
				area
			]);
		}, this));
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
