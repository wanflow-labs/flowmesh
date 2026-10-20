// SPDX-License-Identifier: Apache-2.0
// Untrusted strings (peer names, server messages, log lines) must reach the page as text.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadModule } from './luci-shim.mjs';

const fmtext = loadModule('flowmesh/text.js');
const EVIL = '<b>x</b><img src=x onerror=alert(1)>';

// How LuCI's dom.append (luci-base luci.js) treats children: a lone string goes to innerHTML;
// array members that are not nodes become text nodes. Returns what the page would get.
class FakeNode { constructor() { this.innerHTML = null; this.text = []; this.nodes = []; } }
function luciAppend(node, children) {
	if (Array.isArray(children)) {
		for (const c of children) {
			if (c instanceof FakeNode) node.nodes.push(c);
			else node.text.push(`${c}`);
		}
	}
	else if (children instanceof FakeNode) node.nodes.push(children);
	else if (children != null) node.innerHTML = `${children}`;
	return node;
}

test('the model reproduces the hazard: a bare string becomes markup', () => {
	assert.equal(luciAppend(new FakeNode(), EVIL).innerHTML, EVIL);
});

test('children(): a hostile peer name ends up as text, never innerHTML', () => {
	const n = luciAppend(new FakeNode(), fmtext.children(EVIL));
	assert.equal(n.innerHTML, null);
	assert.deepEqual(n.text, [EVIL]);
});

test('children(): formatted messages and log text stay text', () => {
	const msg = '%s overlaps a network that %s already shares.'.replace('%s', '192.168.1.0/24').replace('%s', EVIL);
	assert.equal(luciAppend(new FakeNode(), fmtext.children(msg)).innerHTML, null);
	const log = ['line 1', `peer ${EVIL} joined`].join('\n');
	assert.deepEqual(luciAppend(new FakeNode(), fmtext.children(log)).text, [log]);
});

test('children(): numbers, nodes, arrays, null', () => {
	assert.deepEqual(fmtext.children(7), ['7']);
	const node = new FakeNode();
	assert.equal(fmtext.children(node), node);
	assert.deepEqual(fmtext.children(['a', node, null, undefined]), ['a', node, '', '']);
	assert.equal(fmtext.children(null), null);
	assert.equal(fmtext.children(undefined), undefined);
});

// overview.js cannot run under node (it needs LuCI), so its source is checked: all rendering goes
// through el()/setContent(), which pass children through fmtext.children().
const here = dirname(fileURLToPath(import.meta.url));
const view = readFileSync(join(here, '..', 'htdocs', 'luci-static', 'resources', 'view', 'flowmesh', 'overview.js'), 'utf8')
	.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

test('overview.js: E() and dom.content() are only used inside el()/setContent()', () => {
	assert.equal((view.match(/\bE\(/g) || []).length, 1, 'E( outside el()');
	assert.match(view, /return E\(tag, attrs, fmtext\.children\(children\)\);/);
	assert.equal((view.match(/dom\.content\(/g) || []).length, 1, 'dom.content( outside setContent()');
	assert.match(view, /return dom\.content\(node, fmtext\.children\(children\)\);/);
	assert.match(view, /'require flowmesh\.text as fmtext'/);
});

test('overview.js: no raw HTML sinks', () => {
	for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'dom.append(', 'dom.create('])
		assert.ok(!view.includes(sink), sink);
});

test('overview.js: modal titles and notification titles are fixed text', () => {
	for (const m of view.matchAll(/ui\.showModal\(([^,]*),/g))
		assert.match(m[1].trim(), /^(null|_\('[^']*'\))$/, m[0]);
	for (const m of view.matchAll(/ui\.addNotification\(([^,]*),/g))
		assert.equal(m[1].trim(), 'null', m[0]);
});
