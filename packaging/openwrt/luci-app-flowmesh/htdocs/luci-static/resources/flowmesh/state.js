// SPDX-License-Identifier: Apache-2.0
'use strict';
'require baseclass';

// Reading `flowmesh status --json` (as passed through by `flowmesh-luci status`) for the page.
// Fields follow the official client's status shape; lists the daemon prints as null when empty
// (TailscaleIPs, Peer, PrimaryRoutes) are read as empty.

var STATES = {
	NeedsLogin: 'needs_login',
	Stopped: 'stopped',
	Starting: 'starting',
	Running: 'running'
};

function list(v) {
	return Array.isArray(v) ? v : [];
}

// "a.b.c.d" -> [4 bytes] or null.
function parseIPv4(s) {
	var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);

	if (!m)
		return null;

	var b = [];

	for (var i = 1; i <= 4; i++) {
		var n = +m[i];

		if (n > 255)
			return null;

		b.push(n);
	}

	return b;
}

// IPv6 text (with :: and an optional dotted IPv4 tail) -> [16 bytes] or null.
function parseIPv6(s) {
	var halves = s.split('::');

	if (halves.length > 2 || s == '')
		return null;

	function groups(part) {
		if (part == '')
			return [];

		var out = [], items = part.split(':');

		for (var i = 0; i < items.length; i++) {
			var g = items[i];

			if (i == items.length - 1 && g.indexOf('.') >= 0) {
				var v4 = parseIPv4(g);

				if (!v4)
					return null;

				out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
			}
			else if (/^[0-9a-fA-F]{1,4}$/.test(g)) {
				out.push(parseInt(g, 16));
			}
			else {
				return null;
			}
		}

		return out;
	}

	var head = groups(halves[0]), tail = halves.length == 2 ? groups(halves[1]) : [];

	if (!head || !tail)
		return null;

	var fill = 8 - head.length - tail.length;

	if ((halves.length == 2 && fill < 1) || (halves.length == 1 && fill != 0))
		return null;

	var all = head.concat(new Array(fill).fill(0), tail), bytes = [];

	for (var j = 0; j < 8; j++)
		bytes.push(all[j] >> 8, all[j] & 255);

	return bytes;
}

// "addr/len" -> {bytes, len} or null.
function parsePrefix(text) {
	var m = /^([^/\s]+)\/(\d{1,3})$/.exec(String(text == null ? '' : text).trim());

	if (!m)
		return null;

	var bytes = m[1].indexOf(':') >= 0 ? parseIPv6(m[1]) : parseIPv4(m[1]), len = +m[2];

	if (!bytes || len > bytes.length * 8)
		return null;

	return { bytes: bytes, len: len };
}

// The first `bits` bits of a and b are equal (same family required).
function samePrefix(a, b, bits) {
	if (a.length != b.length)
		return false;

	for (var i = 0; bits > 0; i++, bits -= 8) {
		var mask = bits >= 8 ? 255 : (0xff << (8 - bits)) & 255;

		if ((a[i] & mask) != (b[i] & mask))
			return false;
	}

	return true;
}

function equal(a, b) {
	return a.len == b.len && samePrefix(a.bytes, b.bytes, a.len);
}

function overlap(a, b) {
	return samePrefix(a.bytes, b.bytes, Math.min(a.len, b.len));
}

function format(bytes, len) {
	if (bytes.length == 4)
		return bytes.join('.') + '/' + len;

	var g = [];

	for (var i = 0; i < 16; i += 2)
		g.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));

	// Shorten the longest run of zero groups (two or more) to "::".
	var best = -1, bestLen = 0;

	for (var s = 0; s < 8; s++) {
		var e = s;

		while (e < 8 && g[e] == '0')
			e++;

		if (e - s > bestLen && e - s > 1) {
			best = s;
			bestLen = e - s;
		}

		if (e > s)
			s = e;
	}

	var text = best < 0 ? g.join(':')
		: g.slice(0, best).join(':') + '::' + g.slice(best + bestLen).join(':');

	return text + '/' + len;
}

function peerPath(p) {
	if (p.CurAddr)
		return 'direct';

	if (p.Active === false)
		return 'idle';

	if (p.PeerRelay)
		return 'peer-relay';

	if (p.Relay)
		return 'relay';

	return 'idle';
}

function peerName(p) {
	if (p.HostName)
		return String(p.HostName);

	return String(p.DNSName || '').split('.')[0];
}

return baseclass.extend({
	// {state, ips, name, peers, primaryRoutes, exitNodeOption, haveNodeKey}; state is one of down,
	// needs_login, stopped, starting, running. Peer = {name, ips, online, path, primaryRoutes}, path
	// one of direct, relay, peer-relay, idle.
	summarize: function(status) {
		var s = (status != null && typeof status == 'object') ? status : {};
		var self = (s.Self != null && typeof s.Self == 'object') ? s.Self : {};
		var state = STATES[s.BackendState] || 'down';
		var peers = [];

		if (state != 'down' && s.Peer != null && typeof s.Peer == 'object') {
			for (var k in s.Peer) {
				var p = s.Peer[k] || {};

				peers.push({
					name: peerName(p),
					ips: list(p.TailscaleIPs).slice(),
					online: p.Online === true,
					path: peerPath(p),
					primaryRoutes: list(p.PrimaryRoutes).slice()
				});
			}
		}

		peers.sort(function(a, b) { return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0); });

		return {
			state: state,
			ips: state == 'down' ? [] : list(s.TailscaleIPs).slice(),
			name: state == 'down' ? '' : String(self.HostName || ''),
			peers: peers,
			primaryRoutes: list(self.PrimaryRoutes).slice(),
			exitNodeOption: self.ExitNodeOption === true,
			haveNodeKey: s.HaveNodeKey === true
		};
	},

	// Whether this router belongs to a mesh (status view) or not yet (join form). A joined router
	// never gets the join form: `up --reset` with a bad key would drop its working connection.
	joined: function(sum) {
		if (!sum || sum.state == 'down' || sum.state == 'needs_login')
			return false;

		return sum.state == 'running' || sum.haveNodeKey || sum.ips.length > 0;
	},

	// [{prefix, state: 'active'|'pending'}] for the routes this router advertises (`wanted`), active
	// once the control server lists them as this node's primary routes.
	routeState: function(wanted, primary) {
		var approved = list(primary).map(parsePrefix).filter(Boolean);

		return list(wanted).map(function(prefix) {
			var p = parsePrefix(prefix);
			var active = !!p && approved.some(function(a) { return equal(a, p); });

			return { prefix: prefix, state: active ? 'active' : 'pending' };
		});
	},

	// [{prefix, peer}] for every one of `mine` that overlaps a route another node shares. Default
	// routes (an exit node's 0.0.0.0/0 and ::/0) overlap everything and are not counted.
	conflicts: function(mine, peers) {
		var out = [];

		list(mine).forEach(function(prefix) {
			var m = parsePrefix(prefix);

			if (!m || m.len == 0)
				return;

			list(peers).forEach(function(peer) {
				var hit = list(peer && peer.primaryRoutes).some(function(r) {
					var p = parsePrefix(r);

					return p && p.len > 0 && overlap(m, p);
				});

				if (hit)
					out.push({ prefix: prefix, peer: peer.name });
			});
		});

		return out;
	},

	// The network an interface address belongs to: "192.168.1.1/24" -> "192.168.1.0/24"; null when
	// the text is not "address/length".
	network: function(cidr) {
		var p = parsePrefix(cidr);

		if (!p)
			return null;

		var bytes = p.bytes.map(function(b, i) {
			var bits = p.len - i * 8;

			return bits >= 8 ? b : (bits <= 0 ? 0 : b & ((0xff << (8 - bits)) & 255));
		});

		return format(bytes, p.len);
	}
});
