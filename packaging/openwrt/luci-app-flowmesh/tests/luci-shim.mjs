// SPDX-License-Identifier: Apache-2.0
// Loads a LuCI JS module (htdocs/luci-static/resources/...) under node the way LuCI's L.require does:
// the leading 'use strict' / 'require <name>' strings name the dependencies, and the source is the
// body of a factory function that returns the module. Only the dependencies given here can be
// required; `baseclass.extend(obj)` hands back `obj` itself, so a test calls the module's functions.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const resources = join(dirname(fileURLToPath(import.meta.url)), '..', 'htdocs', 'luci-static', 'resources');

const builtins = {
	baseclass: { extend: (props) => props },
};

// The 'require' statements at the top of the source, as LuCI's scanner reads them: string literals
// up to the first one that is neither 'use strict' nor a require.
function requires(source) {
	const found = [];
	const re = /^(?:\s|\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)*(['"])(.*?)\1;?/;
	let rest = source;
	for (;;) {
		const m = re.exec(rest);
		if (!m) break;
		const s = m[2];
		const req = /^require[ \t]+(\S+)(?:[ \t]+as[ \t]+([a-zA-Z_]\S*))?$/.exec(s);
		if (req) found.push({ name: req[1], as: req[2] || req[1].replace(/[^a-zA-Z0-9_]/g, '_') });
		else if (s !== 'use strict') break;
		rest = rest.slice(m[0].length);
	}
	return found;
}

export function loadModule(relPath) {
	const source = readFileSync(join(resources, relPath), 'utf8');
	const deps = requires(source);
	const names = deps.map((d) => d.as);
	const values = deps.map((d) => {
		if (!(d.name in builtins)) throw new Error(`${relPath}: the test shim cannot provide '${d.name}'`);
		return builtins[d.name];
	});
	const factory = new Function('window', 'document', 'L', ...names, source);
	return factory(globalThis, undefined, {}, ...values);
}
