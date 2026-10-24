// SPDX-License-Identifier: Apache-2.0
'use strict';
'require baseclass';
'require dom';
'require rpc';
'require ui';
'require flowmesh.state as fmstate';
'require flowmesh.text as fmtext';

// What every FlowMesh page shares: element creation, the helper call, error texts, the
// "join first" notice and applying /etc/config/flowmesh. Everything goes through
// /usr/libexec/flowmesh-luci (rpcd `file exec`, see the luci-app-flowmesh ACL).

// Every element and every content change goes through these two: untrusted strings (peer names,
// server messages, log lines, diagnostics output) must become text nodes, never markup (see
// flowmesh/text.js). tests/text.test.mjs rejects any other E(), dom.content() or innerHTML in this
// file and in the views.
function el(tag, attrs, children) {
	return E(tag, attrs, fmtext.children(children));
}

function setContent(node, children) {
	return dom.content(node, fmtext.children(children));
}

var HELPER = '/usr/libexec/flowmesh-luci';
var SIGNUP_URL = 'https://www.wanflow.com';
var CONSOLE_URL = 'https://console.wanflow.com';
// `up` waits up to 20 s for the node to come up and is stopped at 25 s (netcheck, ping and
// bugreport too): well above LuCI's default 20 s request timeout.
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

// (LuCI's own pages apply staged changes with a rollback timer and rely on reload triggers;
// FlowMesh has none on purpose, so its pages commit flowmesh and push it with `apply` themselves:
// the luci-app-flowmesh ACL grants commit and revert, for flowmesh only.)
var callUciSet = rpc.declare({
	object: 'uci',
	method: 'set',
	params: [ 'config', 'section', 'values' ],
	reject: true
});

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
	return el('a', { href: CONSOLE_URL, target: '_blank', rel: 'noopener' }, _('Open the console'));
}

// The user-facing text for a helper error code (joining: the answer to `up`).
function errorText(res, joining) {
	switch (res.code) {
	case 'key_invalid':
		return _('This join code has expired or was already used. Generate a new one in the console.');
	case 'site_limit':
		return _('Your mesh has reached its site limit.');
	case 'unreachable':
		return _('Cannot reach the mesh server. Check the address and this router\'s Internet connection.');
	case 'timeout':
		if (joining)
			return _('The mesh server did not answer in time. Please try again.');
		return _('This took too long; FlowMesh may still be applying an earlier change. Please try again in a moment.');
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

// An alert box for a failed helper call: the text, the client's own words where they help, and a
// console link where the fix is made there.
function errorBox(res, joining) {
	var body = [ el('p', {}, errorText(res, joining)) ];

	if ((res.code == 'site_limit' || res.code == 'unknown') && res.detail)
		body.push(el('pre', { 'class': 'flowmesh-detail' }, res.detail));

	if (res.code == 'key_invalid' || res.code == 'site_limit')
		body.push(el('p', {}, consoleLink()));

	return el('div', { 'class': 'alert-message warning' }, body);
}

function notifyError(res) {
	ui.addNotification(null, Array.prototype.slice.call(errorBox(res).childNodes), 'danger');
}

function busy(text) {
	ui.showModal(null, [ el('p', { 'class': 'spinning' }, text) ]);
}

// Which page a status calls for: 'down' (no daemon answer), 'join' (not in a mesh yet) or
// 'joined'.
function modeOf(sum) {
	if (sum.state == 'down')
		return 'down';

	return fmstate.joined(sum) ? 'joined' : 'join';
}

// What the pages other than Overview show while the router is not in a mesh, or the service is not
// running: joining and starting happen on Overview.
function joinFirst(mode) {
	var href = L.url('admin', 'services', 'flowmesh', 'overview');

	return el('div', { 'class': 'cbi-section' }, el('div', { 'class': 'alert-message notice' }, [
		el('p', {}, mode == 'down'
			? _('The FlowMesh service is not running. Start it on the Overview page.')
			: _('This router has not joined a mesh yet. Join one on the Overview page first.')),
		el('p', {}, el('a', { 'class': 'btn cbi-button cbi-button-action', 'href': href }, _('Go to Overview')))
	]));
}

// The pages' own styles; LuCI's theme classes do the rest.
function styles() {
	return el('style', {}, [
		'.flowmesh-pending { color: #b8860b; }',
		'.flowmesh-active { color: #3c763d; }',
		'.flowmesh-bad, .cbi-dynlist > .item.flowmesh-bad { color: #c9302c; }',
		'.cbi-dynlist > .item.flowmesh-bad { border-color: #c9302c; }',
		'.flowmesh-muted { opacity: .7; }',
		'.flowmesh-detail { white-space: pre-wrap; word-break: break-word; margin: .5em 0; }',
		'.flowmesh-log { max-height: 40em; overflow: auto; white-space: pre-wrap; font-size: 90%; }',
		'.flowmesh-signup { display: flex; flex-wrap: wrap; align-items: center; gap: .5em 1em; }',
		'.flowmesh-signup p { margin: 0; }',
		'.flowmesh textarea { width: 100%; }',
		'.flowmesh-tag { display: inline-block; padding: 0 .4em; margin: .1em .3em .1em 0; border: 1px solid currentColor; border-radius: 3px; font-size: 85%; white-space: nowrap; }',
		'.flowmesh-routes > div { margin: .15em 0; }',
		'.flowmesh-routes .alert-message { margin: .4em 0; }',
		'.flowmesh-bar { display: flex; flex-wrap: wrap; align-items: center; gap: .5em; margin: .5em 0; }',
		'.flowmesh-nowrap { white-space: nowrap; }',
		'.flowmesh-hint { font-size: 90%; opacity: .8; margin: .5em 0; }'
	].join('\n'));
}

// The page frame: styles, title, a one-line description, then the body (a node or list of nodes).
function page(description, body) {
	return el('div', { 'class': 'flowmesh' }, [
		styles(),
		el('h2', {}, _('FlowMesh')),
		description ? el('div', { 'class': 'cbi-map-descr' }, description) : '',
		el('div', {}, body)
	]);
}

// The text for the exit-node state (Overview, Settings); name: the exit node's name.
function exitStateText(state, name) {
	switch (fmstate.exitStateLabel(state)) {
	case 'active':
		return _('The LAN reaches the Internet through %s').format(name);
	case 'offline_blocked':
		return _('Exit node %s is offline: the LAN has no Internet access (Kill Switch)').format(name);
	case 'offline_fallback':
		return _('Exit node %s is offline: the LAN uses the local Internet connection for now').format(name);
	case 'missing':
		return _('Exit node %s is not available in the mesh').format(name);
	case 'none':
		return _('Not used');
	default:
		return _('Checking…');
	}
}

// The CSS class for that state.
function exitStateClass(state) {
	switch (fmstate.exitStateLabel(state)) {
	case 'active':
		return 'flowmesh-active';
	case 'offline_blocked':
	case 'missing':
		return 'flowmesh-bad';
	case 'offline_fallback':
		return 'flowmesh-pending';
	default:
		return 'flowmesh-muted';
	}
}

// The name of the exit node with mesh address ip (the address itself when it is not in the map).
function exitName(status, ip) {
	var opt = fmstate.exitOptions(status).filter(function(o) { return o.ip == ip; })[0];

	return opt ? opt.name : String(ip || '');
}

// The LAN's own networks, from the lan interface's IPv4 addresses (lan: LuCI's network object, or
// null): what the service shares when no network is listed (flowmesh_lan_networks).
function autoRoutes(lan) {
	var addrs = (lan && lan.getIPAddrs) ? lan.getIPAddrs() : [];

	return addrs.map(fmstate.network).filter(function(n, i, all) {
		return n != null && all.indexOf(n) == i;
	});
}

// The networks this router shares when sharing is on: the listed ones, or else the LAN's.
function wantedRoutes(listed, lan) {
	listed = L.toArray(listed);

	return listed.length ? listed : autoRoutes(lan);
}

// Approval state of a shared network or of the exit node offer: only meaningful while connected.
function approvalLabel(online, active) {
	if (!online)
		return el('span', { 'class': 'flowmesh-muted' }, _('Not shared while disconnected'));

	return active
		? el('span', { 'class': 'flowmesh-active' }, _('Active'))
		: el('span', { 'class': 'flowmesh-pending' }, _('Advertised — waiting for an admin to approve it in the console'));
}

// Commit /etc/config/flowmesh (after setting `values`, {option: value}, when given; otherwise what
// is staged already, e.g. by a form.Map save) and push it to the daemon. Resolves to true when
// applied; failures are shown as a notification.
function applyConfig(values) {
	var staged = values ? callUciSet('flowmesh', 'main', values) : Promise.resolve();

	return staged.then(function() {
		return callUciCommit('flowmesh');
	}).then(function() {
		return helper([ 'apply' ], true);
	}).then(function(res) {
		if (!res.ok)
			notifyError(res);

		return res.ok === true;
	}, function(err) {
		// Not written: drop the staged change too, or the page would show it as set.
		notifyError({ code: 'rpc', detail: String(err && err.message || err) });
		return L.resolveDefault(callUciRevert('flowmesh')).then(function() { return false; });
	});
}

return baseclass.extend({
	el: el,
	setContent: setContent,
	helper: helper,
	consoleLink: consoleLink,
	errorText: errorText,
	errorBox: errorBox,
	notifyError: notifyError,
	busy: busy,
	modeOf: modeOf,
	joinFirst: joinFirst,
	page: page,
	exitStateText: exitStateText,
	exitStateClass: exitStateClass,
	exitName: exitName,
	autoRoutes: autoRoutes,
	wantedRoutes: wantedRoutes,
	approvalLabel: approvalLabel,
	applyConfig: applyConfig,
	SIGNUP_URL: SIGNUP_URL
});
