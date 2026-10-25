// SPDX-License-Identifier: Apache-2.0
// node --test packaging/openwrt/luci-app-flowmesh/tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule } from './luci-shim.mjs';

const st = loadModule('flowmesh/state.js');

// A node as `flowmesh status --json` prints it (crates/flowmesh-daemon/src/status_json.rs).
function node(over) {
	return Object.assign({
		ID: '2', PublicKey: 'nodekey:aa', HostName: 'peer', DNSName: 'peer.mesh.example.', OS: 'linux',
		TailscaleIPs: ['100.64.0.2', 'fd7a:115c:a1e0::2'], CurAddr: '', PeerRelay: '', Relay: 'r1',
		RxBytes: 0, TxBytes: 0, LastSeen: '0001-01-01T00:00:00Z', Online: true, ExitNodeOption: false,
		ExitNode: false, Active: true, PrimaryRoutes: null,
	}, over);
}

function status(over) {
	return Object.assign({
		Version: '0.1.5', TUN: true, BackendState: 'Running', AuthURL: '',
		TailscaleIPs: ['100.64.0.1', 'fd7a:115c:a1e0::1'],
		Self: node({ HostName: 'gw-home', PublicKey: 'nodekey:00', TailscaleIPs: ['100.64.0.1', 'fd7a:115c:a1e0::1'] }),
		Health: [], MagicDNSSuffix: 'mesh.example', CurrentTailnet: null, Peer: null, HaveNodeKey: true,
	}, over);
}

test('summarize: no status at all is down', () => {
	assert.equal(st.summarize(null).state, 'down');
	assert.equal(st.summarize(undefined).state, 'down');
	assert.deepEqual(st.summarize(null).ips, []);
	assert.deepEqual(st.summarize(null).peers, []);
	assert.equal(st.summarize(null).name, '');
	// What flowmesh-luci prints when the daemon does not answer.
	assert.equal(st.summarize({ ok: false, code: 'daemon_down', detail: 'x' }).state, 'down');
});

test('summarize: backend states', () => {
	assert.equal(st.summarize(status({ BackendState: 'NeedsLogin' })).state, 'needs_login');
	assert.equal(st.summarize(status({ BackendState: 'Stopped' })).state, 'stopped');
	assert.equal(st.summarize(status({ BackendState: 'Starting' })).state, 'starting');
	assert.equal(st.summarize(status({ BackendState: 'Running' })).state, 'running');
	assert.equal(st.summarize(status({ BackendState: 'NoState' })).state, 'down');
});

test('summarize: own addresses, name and approved routes', () => {
	const s = st.summarize(status({ Self: node({ HostName: 'gw-home', PrimaryRoutes: ['192.168.1.0/24'], ExitNodeOption: true }) }));
	assert.deepEqual(s.ips, ['100.64.0.1', 'fd7a:115c:a1e0::1']);
	assert.equal(s.name, 'gw-home');
	assert.deepEqual(s.primaryRoutes, ['192.168.1.0/24']);
	assert.equal(s.exitNodeOption, true);
	assert.equal(s.haveNodeKey, true);
});

test('summarize: logged out status (null addresses, no peers)', () => {
	const s = st.summarize(status({ BackendState: 'NeedsLogin', TailscaleIPs: null, Peer: null, HaveNodeKey: undefined,
		Self: { ID: '', HostName: 'OpenWrt', TailscaleIPs: null, CurAddr: '', Relay: '', Online: false, Active: false } }));
	assert.equal(s.state, 'needs_login');
	assert.deepEqual(s.ips, []);
	assert.deepEqual(s.peers, []);
	assert.deepEqual(s.primaryRoutes, []);
	assert.equal(s.haveNodeKey, false);
});

test('summarize: peers and their connection path', () => {
	const s = st.summarize(status({ Peer: {
		'nodekey:a': node({ HostName: 'direct-one', CurAddr: '203.0.113.5:41641', Relay: 'r1' }),
		'nodekey:b': node({ HostName: 'relayed', CurAddr: '', Relay: 'r1' }),
		'nodekey:c': node({ HostName: 'fast', CurAddr: '', PeerRelay: '198.51.100.7:40000', Relay: 'r1' }),
		'nodekey:d': node({ HostName: 'quiet', CurAddr: '', Relay: 'r1', Active: false }),
		'nodekey:e': node({ HostName: 'gone', Online: false, Active: false, TailscaleIPs: ['100.64.0.9'], PrimaryRoutes: ['10.9.0.0/24'] }),
	} }));
	const by = Object.fromEntries(s.peers.map((p) => [p.name, p]));
	assert.equal(by['direct-one'].path, 'direct');
	assert.equal(by.relayed.path, 'relay');
	assert.equal(by.fast.path, 'peer-relay');
	assert.equal(by.quiet.path, 'idle');
	assert.equal(by.gone.online, false);
	assert.deepEqual(by.gone.ips, ['100.64.0.9']);
	assert.deepEqual(by.gone.primaryRoutes, ['10.9.0.0/24']);
	assert.deepEqual(by.relayed.primaryRoutes, []); // PrimaryRoutes: null
	assert.deepEqual(Object.keys(by[s.peers[0].name]).sort(), ['dnsLabel', 'exitNode', 'exitNodeOption', 'ips', 'name', 'online', 'path', 'primaryRoutes', 'rxBytes', 'txBytes']);
	// sorted by name
	assert.deepEqual(s.peers.map((p) => p.name), ['direct-one', 'fast', 'gone', 'quiet', 'relayed']);
});

test('summarize: brief cases — CurAddr set is direct, Relay set with empty CurAddr is relay', () => {
	const s = st.summarize(status({ Peer: {
		k1: { HostName: 'a', CurAddr: '192.0.2.1:41641', Relay: '' },
		k2: { HostName: 'b', CurAddr: '', Relay: 'r1' },
	} }));
	assert.equal(s.peers[0].path, 'direct');
	assert.equal(s.peers[1].path, 'relay');
});

test('summarize: a peer without HostName uses the first DNSName label', () => {
	const s = st.summarize(status({ Peer: { k: node({ HostName: '', DNSName: 'laptop.mesh.example.' }) } }));
	assert.equal(s.peers[0].name, 'laptop');
});

test('joined: decides between the join form and the status view', () => {
	assert.equal(st.joined(st.summarize(null)), false);
	assert.equal(st.joined(st.summarize(status({ BackendState: 'NeedsLogin', HaveNodeKey: undefined, TailscaleIPs: null }))), false);
	assert.equal(st.joined(st.summarize(status({ BackendState: 'Stopped', HaveNodeKey: undefined, TailscaleIPs: null, Self: { HostName: 'x' } }))), false);
	assert.equal(st.joined(st.summarize(status({ BackendState: 'Stopped' }))), true); // `down` after joining
	assert.equal(st.joined(st.summarize(status({ BackendState: 'Starting', TailscaleIPs: null, Self: { HostName: 'x' } }))), true); // restarting, key held
	assert.equal(st.joined(st.summarize(status({ BackendState: 'Starting', HaveNodeKey: undefined, TailscaleIPs: null, Self: { HostName: 'x' } }))), false); // a failed first join retrying
	assert.equal(st.joined(st.summarize(status())), true);
});

test('routeState: approved routes are active, the rest pending', () => {
	assert.deepEqual(st.routeState(['192.168.1.0/24', '192.168.2.0/24'], ['192.168.1.0/24']), [
		{ prefix: '192.168.1.0/24', state: 'active' },
		{ prefix: '192.168.2.0/24', state: 'pending' },
	]);
});

test('routeState: null or missing primary routes mean nothing is approved', () => {
	assert.deepEqual(st.routeState(['192.168.1.0/24'], null), [{ prefix: '192.168.1.0/24', state: 'pending' }]);
	assert.deepEqual(st.routeState(['192.168.1.0/24'], undefined), [{ prefix: '192.168.1.0/24', state: 'pending' }]);
	assert.deepEqual(st.routeState(null, ['192.168.1.0/24']), []);
});

test('routeState: the same network written differently still matches', () => {
	assert.deepEqual(st.routeState(['192.168.1.0/24', 'FD00:0:0:1::/64'], ['192.168.1.0/24', 'fd00:0:0:1::/64']).map((r) => r.state), ['active', 'active']);
	assert.deepEqual(st.routeState(['192.168.1.0/24'], ['192.168.1.0/25']).map((r) => r.state), ['pending']);
});

test('conflicts: any overlap counts, not only equal prefixes', () => {
	assert.deepEqual(st.conflicts(['192.168.1.0/24'], [{ name: 'b', primaryRoutes: ['192.168.0.0/16'] }]), [{ prefix: '192.168.1.0/24', peer: 'b' }]);
	assert.deepEqual(st.conflicts(['192.168.0.0/16'], [{ name: 'b', primaryRoutes: ['192.168.7.0/24'] }]), [{ prefix: '192.168.0.0/16', peer: 'b' }]);
	assert.deepEqual(st.conflicts(['10.1.0.0/24'], [{ name: 'b', primaryRoutes: ['10.2.0.0/24'] }]), []);
});

test('conflicts: IPv6', () => {
	assert.equal(st.conflicts(['fd00:1::/64'], [{ name: 'b', primaryRoutes: ['fd00::/16'] }]).length, 1);
	assert.equal(st.conflicts(['fd00:1::/64'], [{ name: 'b', primaryRoutes: ['fd00:2::/64'] }]).length, 0);
	assert.equal(st.conflicts(['fd00:1::/64'], [{ name: 'b', primaryRoutes: ['10.0.0.0/8'] }]).length, 0); // families never overlap
	assert.equal(st.conflicts(['2001:db8:0:1::/64'], [{ name: 'b', primaryRoutes: ['2001:db8::/48'] }]).length, 1);
});

test('conflicts: null primary routes, several peers, exit routes ignored', () => {
	const peers = [
		{ name: 'a', primaryRoutes: null },
		{ name: 'b' },
		{ name: 'exit', primaryRoutes: ['0.0.0.0/0', '::/0'] },
		{ name: 'c', primaryRoutes: ['192.168.1.128/25', '192.168.9.0/24'] },
		{ name: 'd', primaryRoutes: ['192.168.1.0/24'] },
	];
	assert.deepEqual(st.conflicts(['192.168.1.0/24'], peers), [
		{ prefix: '192.168.1.0/24', peer: 'c' },
		{ prefix: '192.168.1.0/24', peer: 'd' },
	]);
	assert.deepEqual(st.conflicts(null, peers), []);
	assert.deepEqual(st.conflicts(['192.168.1.0/24'], null), []);
});

test('conflicts: malformed prefixes are skipped, not thrown on', () => {
	assert.deepEqual(st.conflicts(['bogus', '192.168.1.0/24'], [{ name: 'b', primaryRoutes: ['nope', '192.168.1.0/24'] }]), [{ prefix: '192.168.1.0/24', peer: 'b' }]);
});

test('network: the network of an interface address', () => {
	assert.equal(st.network('192.168.1.1/24'), '192.168.1.0/24');
	assert.equal(st.network('10.20.30.40/12'), '10.16.0.0/12');
	assert.equal(st.network('172.16.5.4/32'), '172.16.5.4/32');
	assert.equal(st.network('fd00:abcd::1/64'), 'fd00:abcd::/64');
	assert.equal(st.network('192.168.1.1'), null);
	assert.equal(st.network('300.1.1.1/24'), null);
	assert.equal(st.network('192.168.1.1/33'), null);
});

test('summarize: per-peer traffic and exit-node flags', () => {
	const s = st.summarize(status({ Peer: {
		k1: node({ HostName: 'exit', RxBytes: 1536, TxBytes: 42, ExitNodeOption: true, ExitNode: true }),
		k2: node({ HostName: 'plain', RxBytes: undefined, TxBytes: 'x' }),
	} }));
	const by = Object.fromEntries(s.peers.map((p) => [p.name, p]));
	assert.equal(by.exit.rxBytes, 1536);
	assert.equal(by.exit.txBytes, 42);
	assert.equal(by.exit.exitNodeOption, true);
	assert.equal(by.exit.exitNode, true);
	assert.equal(by.plain.rxBytes, 0);
	assert.equal(by.plain.txBytes, 0);
	assert.equal(by.plain.exitNodeOption, false);
	assert.equal(by.plain.exitNode, false);
});

test('formatBytes: binary units, one decimal', () => {
	assert.equal(st.formatBytes(0), '0 B');
	assert.equal(st.formatBytes(1), '1 B');
	assert.equal(st.formatBytes(1023), '1023 B');
	assert.equal(st.formatBytes(1024), '1.0 KiB');
	assert.equal(st.formatBytes(1536), '1.5 KiB');
	assert.equal(st.formatBytes(5 * 1024 * 1024), '5.0 MiB');
	assert.equal(st.formatBytes(3.25 * 1024 ** 3), '3.3 GiB');
	assert.equal(st.formatBytes(2 * 1024 ** 4), '2.0 TiB');
	assert.equal(st.formatBytes(2 * 1024 ** 6), '2048.0 PiB');
	for (const bad of [null, undefined, -5, NaN, 'abc', Infinity])
		assert.equal(st.formatBytes(bad), '0 B', String(bad));
});

test('exitOptions: peers offering themselves as exit node, by name', () => {
	const s = status({ Peer: {
		k1: node({ HostName: 'zeta', TailscaleIPs: ['fd7a:115c:a1e0::5', '100.64.0.5'], ExitNodeOption: true, Online: false }),
		k2: node({ HostName: 'alpha', TailscaleIPs: ['100.64.0.3'], ExitNodeOption: true, ExitNode: true }),
		k3: node({ HostName: 'not-exit', TailscaleIPs: ['100.64.0.4'] }),
		k4: node({ HostName: 'no-v4', TailscaleIPs: ['fd7a:115c:a1e0::9'], ExitNodeOption: true }),
		k5: node({ HostName: 'nulls', TailscaleIPs: null, ExitNodeOption: true }),
	} });
	assert.deepEqual(st.exitOptions(s), [
		{ ip: '100.64.0.3', name: 'alpha', online: true, current: true },
		{ ip: '100.64.0.5', name: 'zeta', online: false, current: false },
	]);
	assert.deepEqual(st.exitOptions(status()), []); // Peer: null
	assert.deepEqual(st.exitOptions(null), []);
	assert.deepEqual(st.exitOptions({ ok: false, code: 'daemon_down' }), []);
});

test('validateRoute: valid networks, normalized to the network address', () => {
	assert.deepEqual(st.validateRoute('192.168.1.0/24'), { ok: true, prefix: '192.168.1.0/24' });
	assert.deepEqual(st.validateRoute(' 192.168.1.77/24 '), { ok: true, prefix: '192.168.1.0/24' });
	assert.deepEqual(st.validateRoute('10.1.2.3/32'), { ok: true, prefix: '10.1.2.3/32' });
	assert.deepEqual(st.validateRoute('FD00:ABCD::1/64'), { ok: true, prefix: 'fd00:abcd::/64' });
	assert.deepEqual(st.validateRoute('2001:db8:0:0:1::/48'), { ok: true, prefix: '2001:db8::/48' });
	// next to the mesh range, not in it
	assert.deepEqual(st.validateRoute('100.128.0.0/16'), { ok: true, prefix: '100.128.0.0/16' });
	assert.deepEqual(st.validateRoute('fd7a:115c:a1e1::/48'), { ok: true, prefix: 'fd7a:115c:a1e1::/48' });
});

test('validateRoute: errors', () => {
	for (const bad of ['', '   ', null, undefined, '192.168.1.0', '192.168.1.0/33', '300.1.1.1/24', 'fd00::/129', 'abc/8', '1.2.3.4/24/1', 'fd00:::1/64'])
		assert.deepEqual(st.validateRoute(bad), { ok: false, error: 'format' }, String(bad));
	assert.deepEqual(st.validateRoute('0.0.0.0/0'), { ok: false, error: 'default' });
	assert.deepEqual(st.validateRoute('::/0'), { ok: false, error: 'default' });
	assert.deepEqual(st.validateRoute('10.0.0.0/0'), { ok: false, error: 'default' });
	assert.deepEqual(st.validateRoute('100.64.0.0/10'), { ok: false, error: 'mesh' });
	assert.deepEqual(st.validateRoute('100.100.1.0/24'), { ok: false, error: 'mesh' });
	assert.deepEqual(st.validateRoute('100.0.0.0/8'), { ok: false, error: 'mesh' }); // contains it
	assert.deepEqual(st.validateRoute('fd7a:115c:a1e0:ab12::/64'), { ok: false, error: 'mesh' });
	assert.deepEqual(st.validateRoute('fd7a::/16'), { ok: false, error: 'mesh' });
});

test('exitStateLabel: the eight states, anything else unknown', () => {
	for (const s of ['none', 'active', 'offline_blocked', 'offline_fallback', 'missing', 'down_blocked', 'down_fallback', 'stopped'])
		assert.equal(st.exitStateLabel(s), s);
	for (const s of ['', null, undefined, 'weird', 7])
		assert.equal(st.exitStateLabel(s), 'unknown', String(s));
	// the helper's answer itself is accepted too
	assert.equal(st.exitStateLabel({ want: '100.64.0.2', state: 'offline_blocked', since: 1 }), 'offline_blocked');
	assert.equal(st.exitStateLabel({ ok: false, code: 'rpc' }), 'unknown');
});

// `flowmesh netcheck --format=json` (crates/flowmesh-cli/src/netcheck.rs json()).
function netcheck(over) {
	return Object.assign({
		Now: '2026-10-24T01:02:03.456Z', UDP: true, IPv6: false, IPv4: true, IPv6CanSend: false, IPv4CanSend: true,
		OSHasIPv6: true, ICMPv4: false, MappingVariesByDestIP: false, UPnP: false, PMP: false, PCP: false,
		PreferredDERP: 1001,
		RegionLatency: { 1000: 25300000, 1001: 4600000, 1002: 120000000 },
		RegionV4Latency: { 1000: 25300000, 1001: 4600000 }, RegionV6Latency: {},
		GlobalV4Counters: { '203.0.113.9:41641': 2, '203.0.113.9:41642': 1 }, GlobalV6Counters: null,
		GlobalV4: '203.0.113.9:41641', GlobalV6: '', CaptivePortal: null,
	}, over);
}

test('netcheckSummary: regions sorted by latency, names from the map, preferred region', () => {
	const r = st.netcheckSummary(netcheck(), { 1000: 'Seoul', 1001: 'Tokyo' });
	assert.equal(r.udp, true);
	assert.equal(r.holePunch, 'easy');
	assert.deepEqual(r.regions, [
		{ id: 1001, name: 'Tokyo', ms: 4.6 },
		{ id: 1000, name: 'Seoul', ms: 25.3 },
		{ id: 1002, name: '1002', ms: 120 },
	]);
	assert.deepEqual(r.preferred, { id: 1001, name: 'Tokyo', ms: 4.6 });
	assert.equal(r.ipv4, '203.0.113.9:41641');
	assert.equal(r.ipv6, '');
});

test('netcheckSummary: hole punching from MappingVariesByDestIP', () => {
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: true })).holePunch, 'hard');
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: false })).holePunch, 'easy');
	// the official client's opt.Bool encodes as a string
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: 'true' })).holePunch, 'hard');
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: 'false' })).holePunch, 'easy');
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: '' })).holePunch, 'unknown');
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: null })).holePunch, 'unknown');
	assert.equal(st.netcheckSummary(netcheck({ MappingVariesByDestIP: undefined })).holePunch, 'unknown');
	// "false" is only known with two mapped addresses to compare, and only with UDP
	assert.equal(st.netcheckSummary(netcheck({ GlobalV4Counters: { '203.0.113.9:41641': 3 } })).holePunch, 'unknown');
	assert.equal(st.netcheckSummary(netcheck({ GlobalV4Counters: null })).holePunch, 'unknown');
	assert.equal(st.netcheckSummary(netcheck({ UDP: false, GlobalV4Counters: null })).holePunch, 'unknown');
});

test('netcheckSummary: no UDP, no regions, no preferred region', () => {
	const r = st.netcheckSummary(netcheck({ UDP: false, PreferredDERP: 0, RegionLatency: {}, MappingVariesByDestIP: false, GlobalV4Counters: null }));
	assert.equal(r.udp, false);
	assert.deepEqual(r.regions, []);
	assert.equal(r.preferred, null);
	// a preferred region that has no latency entry is still named
	assert.deepEqual(st.netcheckSummary(netcheck({ PreferredDERP: 7, RegionLatency: null }), { 7: 'X' }).preferred, { id: 7, name: 'X', ms: null });
});

test('netcheckSummary: garbage in, empty summary out', () => {
	for (const bad of [null, undefined, 'x', 5, { ok: false, code: 'timeout' }]) {
		const r = st.netcheckSummary(bad);
		assert.equal(r.udp, false);
		assert.equal(r.holePunch, 'unknown');
		assert.deepEqual(r.regions, []);
		assert.equal(r.preferred, null);
	}
	const r = st.netcheckSummary(netcheck({ RegionLatency: { abc: 5, 1000: 'slow', 1001: -1, 1002: 3000000 } }));
	assert.deepEqual(r.regions, [{ id: 1002, name: '1002', ms: 3 }]);
});

test('netcheckSummary: relay names that carry an internal product name are not shown', () => {
	const r = st.netcheckSummary(netcheck(), { 1000: 'Headscale Embedded DERP', 1001: 'my tailscale relay', 1002: '' });
	assert.deepEqual(r.regions.map((x) => x.name), ['1001', '1000', '1002']);
});

test('regionNames: the relay regions of `flowmesh-luci regions`', () => {
	assert.deepEqual(st.regionNames({ ok: true, regions: [{ id: 1000, code: 'r1', name: 'Seoul' }, { id: '1001', code: 'r2', name: '' }] }),
		{ 1000: 'Seoul', 1001: 'r2' });
	assert.deepEqual(st.regionNames({ ok: false, code: 'daemon_down' }), {});
	assert.deepEqual(st.regionNames(null), {});
	assert.deepEqual(st.regionNames({ ok: true, regions: [{ id: 'x', name: 'bad' }, null] }), {});
});

test('dnsLabel: the first label of a DNS name, the name the mesh answers for', () => {
	assert.equal(st.dnsLabel('sungs-iphone.mesh.example.'), 'sungs-iphone');
	assert.equal(st.dnsLabel('sungs-iphone.mesh.example'), 'sungs-iphone');
	assert.equal(st.dnsLabel('gw.'), 'gw');
	assert.equal(st.dnsLabel('GW-Home.Mesh.Example.'), 'GW-Home');
	for (const bad of ['', '.', '..', null, undefined, 7, {}, ' '])
		assert.equal(st.dnsLabel(bad), '', String(bad));
});

test('summarize: peers and self carry the DNS label (not the free-form HostName)', () => {
	const s = st.summarize(status({
		Self: node({ HostName: 'gw-home', DNSName: 'gw-home.mesh.example.' }),
		Peer: {
			k1: node({ HostName: "Sung's iPhone", DNSName: 'sungs-iphone.mesh.example.' }),
			k2: node({ HostName: 'nodns', DNSName: undefined }),
		},
	}));
	const by = Object.fromEntries(s.peers.map((p) => [p.name, p]));
	assert.equal(by["Sung's iPhone"].dnsLabel, 'sungs-iphone');
	assert.equal(by.nodns.dnsLabel, '');
	assert.equal(s.dnsLabel, 'gw-home');
	assert.equal(st.summarize(null).dnsLabel, '');
});

test('nameExample: a peer name the mesh resolves, or nothing', () => {
	const peers = [
		{ name: "Sung's iPhone", dnsLabel: 'sungs-iphone', online: false },
		{ name: 'nas', dnsLabel: 'nas', online: true },
	];
	assert.equal(st.nameExample({ peers, dnsLabel: 'gw' }, 'mesh.example'), 'nas.mesh.example');
	assert.equal(st.nameExample({ peers: [peers[0]], dnsLabel: 'gw' }, 'mesh.example.'), 'sungs-iphone.mesh.example');
	assert.equal(st.nameExample({ peers: [{ name: 'x', dnsLabel: '', online: true }], dnsLabel: 'gw' }, 'mesh.example'), 'gw.mesh.example');
	assert.equal(st.nameExample({ peers: [{ name: 'x', dnsLabel: '', online: true }], dnsLabel: '' }, 'mesh.example'), '');
	assert.equal(st.nameExample({ peers, dnsLabel: 'gw' }, ''), '');
	assert.equal(st.nameExample({ peers, dnsLabel: 'gw' }, null), '');
	assert.equal(st.nameExample(null, 'mesh.example'), '');
});
