// SPDX-License-Identifier: Apache-2.0
// Untrusted strings (peer names, server messages, log lines) must reach the page as text.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
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

// The pages cannot run under node (they need LuCI), so their source is checked: all rendering goes
// through el()/setContent() in flowmesh/common.js, which pass children through fmtext.children().
const here = dirname(fileURLToPath(import.meta.url));
const resources = join(here, '..', 'htdocs', 'luci-static', 'resources');
const strip = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const read = (rel) => strip(readFileSync(join(resources, rel), 'utf8'));
const viewDir = join(resources, 'view', 'flowmesh');
const views = readdirSync(viewDir).filter((f) => f.endsWith('.js')).sort();
const common = read('flowmesh/common.js');

test('every page is checked', () => {
	assert.deepEqual(views, ['devices.js', 'diagnostics.js', 'logs.js', 'overview.js', 'settings.js']);
});

test('common.js: E() and dom.content() are only used inside el()/setContent()', () => {
	assert.equal((common.match(/\bE\(/g) || []).length, 1, 'E( outside el()');
	assert.match(common, /return E\(tag, attrs, fmtext\.children\(children\)\);/);
	assert.equal((common.match(/dom\.content\(/g) || []).length, 1, 'dom.content( outside setContent()');
	assert.match(common, /return dom\.content\(node, fmtext\.children\(children\)\);/);
	assert.match(common, /'require flowmesh\.text as fmtext'/);
});

// The top-level comma-separated arguments of a call ("a, f(b, c), 'd, e'" -> 3), quotes and escapes
// respected.
function splitArgs(text) {
	const out = [];
	let depth = 0, quote = null, cur = '';
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (quote) {
			cur += c;
			if (c == '\\') cur += text[++i];
			else if (c == quote) quote = null;
		}
		else if (c == "'" || c == '"') { quote = c; cur += c; }
		else if (c == '(' || c == '[' || c == '{') { depth++; cur += c; }
		else if (c == ')' || c == ']' || c == '}') { depth--; cur += c; }
		else if (c == ',' && depth == 0) { out.push(cur); cur = ''; }
		else cur += c;
	}
	out.push(cur);
	return out;
}

test('splitArgs', () => {
	assert.deepEqual(splitArgs("a, f(b, c), 'd, e', _('x\\'s, y')").map((x) => x.trim()), ['a', 'f(b, c)', "'d, e'", "_('x\\'s, y')"]);
});

const SINKS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'dom.append(', 'dom.create(',
	'dom.content(', 'createContextualFragment', 'DOMParser', '.html('];

for (const file of ['flowmesh/common.js', ...views.map((v) => `view/flowmesh/${v}`)]) {
	const src = read(file);
	const isView = file.startsWith('view/');

	if (isView) {
		test(`${file}: renders only through fm.el()/fm.setContent()`, () => {
			assert.equal((src.match(/\bE\(/g) || []).length, 0, 'E(');
			assert.match(src, /'require flowmesh\.common as fm'/);
		});
	}

	test(`${file}: no raw HTML sinks`, () => {
		for (const sink of SINKS) {
			if (sink == 'dom.content(' && !isView) continue; // (setContent itself, checked above)
			assert.ok(!src.includes(sink), sink);
		}
	});

	test(`${file}: modal titles and notification titles are fixed text`, () => {
		for (const m of src.matchAll(/ui\.showModal\(([^,]*),/g))
			assert.match(m[1].trim(), /^(null|_\('[^']*'\))$/, m[0]);
		for (const m of src.matchAll(/ui\.addNotification\(([^,]*),/g))
			assert.equal(m[1].trim(), 'null', m[0]);
	});

	// LuCI renders form titles, descriptions and section titles as markup: only fixed text there.
	test(`${file}: form titles and descriptions are fixed text`, () => {
		for (const m of src.matchAll(/\.(option|section)\(([^\n]*)\);$/gm)) {
			const args = splitArgs(m[2]).slice(m[1] == 'section' ? 3 : 2);
			for (const a of args)
				assert.match(a.trim(), /^(null|_\('(?:[^'\\]|\\.)*'\))$/, m[0]);
		}
		assert.equal((src.match(/\.(option|section)\(/g) || []).length, (src.match(/\.(option|section)\([^\n]*\);$/gm) || []).length,
			'every .option()/.section() call fits on one line (so that this check sees it)');
		for (const m of src.matchAll(/\.description\s*=|\.title\s*=/g))
			assert.fail(`${file}: ${m[0]} set outside the constructor`);
	});
}

// (LuCI wraps each file in a function the same way: a syntax error would only show in the browser.)
test('every page and module parses as a LuCI module body', () => {
	const files = ['flowmesh/common.js', 'flowmesh/state.js', 'flowmesh/text.js', 'flowmesh/joincode.js', ...views.map((v) => `view/flowmesh/${v}`)];
	for (const f of files)
		assert.doesNotThrow(() => new Function('L', 'E', readFileSync(join(resources, f), 'utf8')), f);
});
