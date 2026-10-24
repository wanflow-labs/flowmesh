// SPDX-License-Identifier: Apache-2.0
// Every text the pages show is in the template and translated; none names the software underneath.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const app = join(dirname(fileURLToPath(import.meta.url)), '..');
const resources = join(app, 'htdocs', 'luci-static', 'resources');
const sources = [
	...readdirSync(join(resources, 'flowmesh')).map((f) => join(resources, 'flowmesh', f)),
	...readdirSync(join(resources, 'view', 'flowmesh')).map((f) => join(resources, 'view', 'flowmesh', f)),
].filter((f) => f.endsWith('.js'));

const used = new Set();
for (const f of sources)
	for (const m of readFileSync(f, 'utf8').matchAll(/\b_\('((?:[^'\\]|\\.)*)'\)/g))
		used.add(m[1].replace(/\\(.)/g, '$1'));
for (const m of readFileSync(join(app, 'root/usr/share/luci/menu.d/luci-app-flowmesh.json'), 'utf8').matchAll(/"title": "([^"]+)"/g))
	if (m[1] != 'FlowMesh') used.add(m[1]);

// {msgid: msgstr}
function parsePo(text) {
	const out = {};
	let id = null, field = null;
	for (const line of text.split('\n')) {
		let m;
		if ((m = /^msgid (".*")$/.exec(line))) { id = JSON.parse(m[1]); field = 'id'; }
		else if ((m = /^msgstr (".*")$/.exec(line))) { out[id] = JSON.parse(m[1]); field = 'str'; }
		else if ((m = /^(".*")$/.exec(line)) && id != null) {
			if (field == 'id') id += JSON.parse(m[1]);
			else out[id] += JSON.parse(m[1]);
		}
	}
	delete out[''];
	return out;
}

const pot = parsePo(readFileSync(join(app, 'po/templates/flowmesh.pot'), 'utf8'));
const zh = parsePo(readFileSync(join(app, 'po/zh_Hans/flowmesh.po'), 'utf8'));

test('every text used is in the template and translated to Chinese', () => {
	for (const id of used) {
		assert.ok(id in pot, `not in flowmesh.pot: ${id}`);
		assert.ok(zh[id], `no zh_Hans translation: ${id}`);
	}
});

test('no stale template entries', () => {
	for (const id of Object.keys(pot))
		assert.ok(used.has(id) || id == 'Grant access to FlowMesh', `unused: ${id}`);
});

test('placeholders survive translation', () => {
	for (const [id, str] of Object.entries(zh)) {
		const ph = (s) => (s.match(/%[sd]/g) || []).join('');
		assert.equal(ph(str), ph(id), id);
	}
});

test('no internal product names in what the pages show', () => {
	for (const s of [...used, ...Object.values(zh)])
		assert.doesNotMatch(s, /tailscale|headscale|derp|wireguard/i, s);
});
