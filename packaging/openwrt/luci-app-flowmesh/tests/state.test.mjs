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
	assert.deepEqual(Object.keys(by[s.peers[0].name]).sort(), ['ips', 'name', 'online', 'path', 'primaryRoutes']);
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
