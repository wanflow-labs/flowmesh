// SPDX-License-Identifier: Apache-2.0
'use strict';
'require baseclass';

// What the join box accepts:
//   - a join code, wanflow://<base64url of {"v":1,"s":"<server URL>","k":"<auth key>"}>, unpadded
//     (padding and the standard alphabet are tolerated);
//   - the console's Linux install command, read for --login-server and --auth-key (or --authkey);
// each with any surrounding white space. parse() returns {ok:true, server, key} or {ok:false, error}
// with error 'empty', 'version' (a code newer than this plugin) or 'format'.

var VERSION = 1;
var PREFIX = 'wanflow://';

function fail(error) {
	return { ok: false, error: error };
}

function isServer(s) {
	return typeof s == 'string' && /^https?:\/\/[^\s'"]+$/.test(s);
}

function isKey(k) {
	return typeof k == 'string' && /^\S+$/.test(k);
}

// The UTF-8 text a base64url (or base64) string encodes, or null.
function decodeBase64(text) {
	var s = text.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');

	if (!/^[A-Za-z0-9+/]*$/.test(s) || s.length % 4 == 1)
		return null;

	while (s.length % 4)
		s += '=';

	try {
		var bin = window.atob(s), bytes = new Uint8Array(bin.length);

		for (var i = 0; i < bin.length; i++)
			bytes[i] = bin.charCodeAt(i);

		return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
	}
	catch (e) {
		return null;
	}
}

function parseCode(payload) {
	var json = payload ? decodeBase64(payload) : null, obj;

	if (json == null)
		return fail('format');

	try {
		obj = JSON.parse(json);
	}
	catch (e) {
		return fail('format');
	}

	if (obj == null || typeof obj != 'object' || Array.isArray(obj) || typeof obj.v != 'number')
		return fail('format');

	if (obj.v > VERSION)
		return fail('version');

	if (obj.v != VERSION || !isServer(obj.s) || !isKey(obj.k))
		return fail('format');

	return { ok: true, server: obj.s, key: obj.k };
}

// The value of a --name=value / --name value option in a shell command line: single-quoted (as
// escapeshellarg writes it), double-quoted or bare.
function option(text, names) {
	var re = new RegExp('(?:^|\\s)--(?:' + names + ')(?:=|\\s+)(?:\'([^\']*)\'|"([^"]*)"|([^\\s\'"\\\\]+))');
	var m = re.exec(text);

	return m ? (m[1] != null ? m[1] : (m[2] != null ? m[2] : m[3])) : null;
}

function parseCommand(text) {
	var server = option(text, 'login-server'), key = option(text, 'auth-key|authkey');

	if (!isServer(server) || !isKey(key))
		return fail('format');

	return { ok: true, server: server, key: key };
}

return baseclass.extend({
	VERSION: VERSION,

	parse: function(text) {
		var t = (text == null) ? '' : String(text).trim();

		if (t == '')
			return fail('empty');

		if (t.slice(0, PREFIX.length).toLowerCase() == PREFIX)
			return parseCode(t.slice(PREFIX.length));

		if (/--login-server/.test(t))
			return parseCommand(t);

		return fail('format');
	}
});
