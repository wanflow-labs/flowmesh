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

// A byte counter: a non-negative finite number, else 0.
function count(n) {
	return (typeof n == 'number' && isFinite(n) && n > 0) ? n : 0;
}

// The mesh's own address ranges (100.64.0.0/10 and fd7a:115c:a1e0::/48).
var MESH_RANGES = [ '100.64.0.0/10', 'fd7a:115c:a1e0::/48' ].map(parsePrefix);

// Relay region names come from the control server: one that names the software behind it is not
// shown (the page never names it), the region ID is.
var INTERNAL_NAME = /tailscale|headscale|derp|wireguard/i;

var EXIT_STATES = [ 'none', 'active', 'offline_blocked', 'offline_fallback', 'missing', 'down_blocked', 'down_fallback', 'stopped' ];

// The network an address/length belongs to ("192.168.1.1/24" -> "192.168.1.0/24"), or null.
function network(cidr) {
	var p = parsePrefix(cidr);

	if (!p)
		return null;

	var bytes = p.bytes.map(function(b, i) {
		var bits = p.len - i * 8;

		return bits >= 8 ? b : (bits <= 0 ? 0 : b & ((0xff << (8 - bits)) & 255));
	});

	return format(bytes, p.len);
}

// The first label of a DNS name ("sungs-iphone.mesh.example." -> "sungs-iphone"): the name the
// mesh's resolver answers for, unlike HostName (free text such as "Sung's iPhone"). '' without one.
function dnsLabel(name) {
	if (typeof name != 'string')
		return '';

	return name.trim().replace(/\.+$/, '').split('.')[0];
}

function peerName(p) {
	if (p.HostName)
		return String(p.HostName);

	return String(p.DNSName || '').split('.')[0];
}

return baseclass.extend({
	// {state, ips, name, peers, primaryRoutes, exitNodeOption, haveNodeKey}; state is one of down,
	// needs_login, stopped, starting, running. Peer = {name, ips, online, path, primaryRoutes,
	// rxBytes, txBytes, exitNodeOption, exitNode}, path one of direct, relay, peer-relay, idle;
	// exitNode: it is this router's exit node now.
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
					primaryRoutes: list(p.PrimaryRoutes).slice(),
					rxBytes: count(p.RxBytes),
					txBytes: count(p.TxBytes),
					exitNodeOption: p.ExitNodeOption === true,
					exitNode: p.ExitNode === true,
					dnsLabel: dnsLabel(p.DNSName)
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
			haveNodeKey: s.HaveNodeKey === true,
			dnsLabel: state == 'down' ? '' : dnsLabel(self.DNSName)
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

	// "1.5 KiB": binary units, one decimal from KiB up; anything that is not a count is "0 B".
	formatBytes: function(n) {
		var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB' ], i = 0;

		n = count(n);

		while (n >= 1024 && i < units.length - 1) {
			n /= 1024;
			i++;
		}

		return i == 0 ? Math.floor(n) + ' B' : n.toFixed(1) + ' ' + units[i];
	},

	// [{ip, name, online, current}] for the peers offering themselves as exit node, by name. ip is
	// the peer's mesh IPv4 address (what use_exit_node holds); a peer without one is left out.
	exitOptions: function(status) {
		var s = (status != null && typeof status == 'object') ? status : {}, out = [];

		if (s.Peer == null || typeof s.Peer != 'object')
			return out;

		for (var k in s.Peer) {
			var p = s.Peer[k] || {};
			var ip = list(p.TailscaleIPs).filter(function(a) { return parseIPv4(String(a)) != null; })[0];

			if (p.ExitNodeOption === true && ip)
				out.push({ ip: ip, name: peerName(p), online: p.Online === true, current: p.ExitNode === true });
		}

		return out.sort(function(a, b) { return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0); });
	},

	// A network to share: {ok:true, prefix} (normalized to its network address) or {ok:false, error}
	// with error 'format' (not addr/len), 'default' (a default route: that is the exit node
	// switch) or 'mesh' (overlaps the mesh's own addresses).
	validateRoute: function(cidr) {
		var p = parsePrefix(cidr);

		if (!p)
			return { ok: false, error: 'format' };

		if (p.len == 0)
			return { ok: false, error: 'default' };

		if (MESH_RANGES.some(function(m) { return m.bytes.length == p.bytes.length && overlap(m, p); }))
			return { ok: false, error: 'mesh' };

		return { ok: true, prefix: network(cidr) };
	},

	// The exit-node state the page shows: none, active, offline_blocked, offline_fallback, missing,
	// down_blocked, down_fallback (FlowMesh itself not running), stopped (the user disconnected or
	// logged out), or unknown. Takes the state or `flowmesh-luci exitstate`'s whole answer.
	exitStateLabel: function(state) {
		if (state != null && typeof state == 'object')
			state = state.state;

		return EXIT_STATES.indexOf(state) >= 0 ? state : 'unknown';
	},

	// {id: name} for the relay regions `flowmesh-luci regions` lists (the code where a region has no
	// name).
	regionNames: function(res) {
		var out = {};

		list(res && res.ok && res.regions).forEach(function(r) {
			var id = r ? +r.id : NaN;

			if (r && id > 0 && Math.floor(id) == id)
				out[id] = String(r.name || r.code || '');
		});

		return out;
	},

	// The parts of `flowmesh netcheck --format=json` the page shows: {udp, holePunch, regions,
	// preferred, ipv4, ipv6}. holePunch is 'hard' when the public mapping varies by destination,
	// 'easy' when two relay probes saw the same mapping, else 'unknown'. regions: [{id, name, ms}],
	// fastest first; names from `names` ({id: name}, see regionNames), else the ID.
	netcheckSummary: function(json, names) {
		var r = (json != null && typeof json == 'object' && json.ok !== false) ? json : {};
		var n = (names != null && typeof names == 'object') ? names : {};
		var udp = r.UDP === true, varies = r.MappingVariesByDestIP, counters = 0;

		if (r.GlobalV4Counters != null && typeof r.GlobalV4Counters == 'object')
			counters = Object.keys(r.GlobalV4Counters).length;

		var holePunch = 'unknown';

		if (varies === true || varies === 'true')
			holePunch = 'hard';
		else if ((varies === false || varies === 'false') && udp && counters > 1)
			holePunch = 'easy';

		function nameOf(id) {
			var name = n[id] != null ? String(n[id]) : '';

			return (name == '' || INTERNAL_NAME.test(name)) ? String(id) : name;
		}

		var regions = [], lat = (r.RegionLatency != null && typeof r.RegionLatency == 'object') ? r.RegionLatency : {};

		for (var k in lat) {
			var id = +k, ns = lat[k];

			if (!(id > 0) || Math.floor(id) != id || typeof ns != 'number' || !isFinite(ns) || ns < 0)
				continue;

			regions.push({ id: id, name: nameOf(id), ms: Math.round(ns / 1e5) / 10 });
		}

		regions.sort(function(a, b) { return a.ms - b.ms || a.id - b.id; });

		var pid = +r.PreferredDERP, preferred = null;

		if (pid > 0) {
			preferred = regions.filter(function(x) { return x.id == pid; })[0] || { id: pid, name: nameOf(pid), ms: null };
		}

		return {
			udp: udp,
			holePunch: holePunch,
			regions: regions,
			preferred: preferred,
			ipv4: String(r.GlobalV4 || ''),
			ipv6: String(r.GlobalV6 || '')
		};
	},

	dnsLabel: dnsLabel,

	// A mesh name to try from the LAN ("nas.mesh.example"): an online peer's DNS label (else any
	// peer's, else this router's) with the mesh suffix; '' when there is no such name or no suffix.
	nameExample: function(sum, suffix) {
		suffix = (typeof suffix == 'string') ? suffix.trim().replace(/^\.+|\.+$/g, '') : '';

		if (!sum || !suffix)
			return '';

		var peers = list(sum.peers).filter(function(p) { return p && p.dnsLabel; });
		var label = (peers.filter(function(p) { return p.online; })[0] || peers[0] || {}).dnsLabel || sum.dnsLabel || '';

		return label ? label + '.' + suffix : '';
	},

	// The network an interface address belongs to: "192.168.1.1/24" -> "192.168.1.0/24"; null when
	// the text is not "address/length".
	network: network
});
