// SPDX-License-Identifier: Apache-2.0
'use strict';
'require baseclass';

// LuCI's E() and dom.content() put a lone string child into innerHTML (strings inside an array
// become text nodes). Peer names, server messages and log lines come from other machines, so the
// page never hands LuCI a bare string: children() turns every string into a one-element array.

function children(c) {
	if (typeof c == 'string' || typeof c == 'number')
		return [ String(c) ];

	// (null inside an array would become the text "null")
	if (Array.isArray(c))
		return c.map(function(x) { return x == null ? '' : x; });

	return c;
}

return baseclass.extend({
	children: children
});
