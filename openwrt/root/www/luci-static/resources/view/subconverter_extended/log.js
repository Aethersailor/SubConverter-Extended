'use strict';
'require view';
'require poll';
'require subconverter_extended.api as api';

function renderLogs(data) {
	const logs = data[0] || {};
	const status = data[1] || {};
	const updater = data[2] || {};
	const diagnostics = {
		service: status.service || {},
		config: status.config || {},
		build: status.build || {},
		update: updater
	};

	return E('div', {}, [
		E('h3', {}, _('Service log')),
		E('pre', { style: 'max-height: 45vh; overflow: auto; white-space: pre-wrap' }, [ logs.lines || _('No matching log entries.') ]),
		E('h3', {}, _('Status and update diagnostics')),
		E('pre', { style: 'max-height: 45vh; overflow: auto; white-space: pre-wrap' }, [ JSON.stringify(diagnostics, null, 2) ])
	]);
}

function loadData() {
	return Promise.all([ api.logs(), api.status(), api.updateStatus() ]);
}

return view.extend({
	load: loadData,

	render: function(data) {
		const live = E('div', {}, renderLogs(data));

		poll.add(function() {
			return loadData().then(function(fresh) {
				live.replaceChildren(renderLogs(fresh));
			}).catch(api.notifyError);
		}, 5);

		return E('div', {}, [
			E('h2', {}, _('SubConverter-Extended - Logs')),
			E('p', {}, _('Only the fixed service log filter and sanitized status documents are exposed to LuCI.')),
			live
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
