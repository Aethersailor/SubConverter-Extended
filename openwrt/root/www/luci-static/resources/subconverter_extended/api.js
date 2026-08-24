'use strict';
'require rpc';
'require ui';
'require baseclass';

const calls = {
	status: rpc.declare({ object: 'luci.subconverter_extended', method: 'status' }),
	updateStatus: rpc.declare({ object: 'luci.subconverter_extended', method: 'update_status' }),
	logs: rpc.declare({ object: 'luci.subconverter_extended', method: 'logs' }),
	serviceAction: rpc.declare({ object: 'luci.subconverter_extended', method: 'service_action', params: [ 'action' ] }),
	updateAction: rpc.declare({ object: 'luci.subconverter_extended', method: 'update_action', params: [ 'action' ] })
};

function checked(promise) {
	return Promise.resolve(promise).then(function(result) {
		if (!result || result.ok === false) {
			const error = new Error(_('Operation failed'));
			error.detail = result && result.error ? result.error : _('The backend returned no usable result.');
			error.code = result && result.error_code ? result.error_code : 'backend_error';
			throw error;
		}
		return result;
	});
}

function present(promise) {
	return Promise.resolve(promise).then(function(result) {
		if (!result) {
			const error = new Error(_('Operation failed'));
			error.detail = _('The backend returned no usable result.');
			error.code = 'backend_empty_result';
			throw error;
		}
		return result;
	});
}

function detailNode(summary, detail) {
	return E('details', {}, [
		E('summary', {}, summary),
		E('pre', { style: 'white-space: pre-wrap' }, [ String(detail) ])
	]);
}

function notifyError(error) {
	const message = error && error.message ? error.message : _('Operation failed');
	const detail = error && error.detail;
	const nodes = [ E('p', {}, [ message ]) ];
	if (detail && detail !== message)
		nodes.push(detailNode(_('Technical details'), detail));
	ui.addNotification(null, E('div', {}, nodes), 'error');
}

return baseclass.extend({
	detailNode,
	notifyError,
	status: function() { return checked(calls.status()); },
	updateStatus: function() { return present(calls.updateStatus()); },
	logs: function() { return checked(calls.logs()); },
	serviceAction: function(action) { return checked(calls.serviceAction(action)); },
	updateAction: function(action) { return checked(calls.updateAction(action)); }
});
