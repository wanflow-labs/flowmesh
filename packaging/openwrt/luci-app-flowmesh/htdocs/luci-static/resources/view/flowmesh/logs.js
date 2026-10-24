// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require ui';
'require flowmesh.common as fm';

// Services -> FlowMesh -> Logs: the last FlowMesh lines of the system log. Available whether or not
// the router has joined a mesh (it is where a failed join is explained).

var el = fm.el, setContent = fm.setContent;

return view.extend({
	load: function() {
		return fm.helper([ 'logs' ]);
	},

	render: function(res) {
		this.logBox = el('pre', { 'class': 'flowmesh-log' });
		this.show(res);

		return fm.page(_('The latest FlowMesh lines of the system log, newest at the bottom.'), el('div', { 'class': 'cbi-section' }, [
			el('div', { 'class': 'flowmesh-bar' }, el('button', {
				'class': 'btn cbi-button',
				'click': ui.createHandlerFn(this, 'handleRefresh')
			}, _('Refresh'))),
			this.logBox
		]));
	},

	show: function(res) {
		var lines = (res && res.ok && Array.isArray(res.lines)) ? res.lines : null;

		setContent(this.logBox, lines ? (lines.length ? lines.join('\n') : _('No log lines.')) : fm.errorText(res || {}));

		if (lines)
			window.requestAnimationFrame(L.bind(function() { this.logBox.scrollTop = this.logBox.scrollHeight; }, this));
	},

	handleRefresh: function() {
		return fm.helper([ 'logs' ]).then(L.bind(this.show, this));
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
