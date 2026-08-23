'use strict';
'require view';
'require poll';
'require ui';
'require subconverter_extended.api as api';

function text(value, fallback) {
	return value === undefined || value === null || value === '' ? fallback : String(value);
}

function yesNo(value) {
	return value ? _('Yes') : _('No');
}

function serviceState(status) {
	if (!status.service || status.service.running !== true)
		return _('Stopped');

	const labels = {
		configured: _('Running; runtime endpoint configured'),
		starting: _('Starting'),
		stopped: _('Stopped')
	};
	return labels[status.service.health] || _('Running');
}

function updateState(status) {
	const labels = {
		idle: _('Idle'),
		queued: _('Queued'),
		preparing: _('Preparing'),
		checking: _('Checking'),
		available: _('Update available'),
		up_to_date: _('Up to date'),
		downloading: _('Downloading'),
		verifying: _('Verifying'),
		verified: _('Verified'),
		stopping: _('Stopping service'),
		installing: _('Installing'),
		validating: _('Validating'),
		completed: _('Completed'),
		rolling_back: _('Rolling back'),
		rolled_back: _('Rolled back'),
		success: _('Completed'),
		error: _('Failed'),
		recovering: _('Recovering'),
		recovered: _('Recovered'),
		recovery_failed: _('Recovery failed'),
		configuration_error: _('Installed; configuration reload failed'),
		updater_error: _('Installed; updater reload failed'),
		newer_local: _('Local build is newer'),
		unavailable: _('Unavailable')
	};
	return labels[status && status.state] || text(status && status.state, _('Not checked'));
}

function updateBusy(status) {
	return [ 'queued', 'preparing', 'checking', 'downloading', 'verified',
		'stopping', 'installing', 'validating', 'rolling_back', 'recovering' ]
		.indexOf(status && status.state) >= 0;
}

function endpoint(port, path) {
	let host = window.location.hostname;
	if (host.indexOf(':') >= 0 && host.charAt(0) !== '[')
		host = '[' + host + ']';
	return 'http://' + host + ':' + port + path;
}

function actionButton(label, action, status, updater, primary) {
	const running = status.service && status.service.running === true;
	let disabled = updateBusy(updater);
	if (action === 'start')
		disabled = disabled || running;
	else if (action === 'stop' || action === 'restart')
		disabled = disabled || !running;

	return E('button', {
		class: primary ? 'btn cbi-button-positive' : 'btn cbi-button-action',
		disabled: disabled ? '' : null,
		click: function(event) {
			const button = event.currentTarget;
			button.disabled = true;
			return api.serviceAction(action).then(function() {
				ui.addNotification(null, E('p', {}, [ _('Service action completed.') ]), 'info');
				window.setTimeout(function() { window.location.reload(); }, 500);
			}).catch(function(error) {
				button.disabled = disabled;
				api.notifyError(error);
			});
		}
	}, [ label ]);
}

function renderStatus(status, updater) {
	const config = status.config || {};
	const build = status.build || {};
	const service = status.service || {};
	const port = config.listen_port || 25500;
	const effectivePort = config.effective_listen_port || port;
	const revision = build.revision ? String(build.revision).slice(0, 12) : null;
	const inherited = _('Inherited from pref.toml');
	const rows = [
		[ _('Service status'), serviceState(status) ],
		[ _('Start at boot'), yesNo(service.enabled === true) ],
		[ _('Version'), text(build.version, _('Unavailable')) ],
		[ _('Revision'), text(revision, _('Unavailable')) ],
		[ _('Build date'), text(build.build_date, _('Unavailable')) ],
		[ _('Configuration file'), text(config.config_file, '/etc/subconverter/pref.toml') ],
		[ _('Listen address override'), text(config.listen_address, inherited) ],
		[ _('Listen port override'), text(config.listen_port, inherited) ],
		[ _('Effective listen address'), text(config.effective_listen_address, _('Unavailable')) ],
		[ _('Effective listen port'), text(effectivePort, _('Unavailable')) ],
		[ _('Security profile override'), text(config.security_profile, inherited) ],
		[ _('Public upload override'), text(config.allow_public_upload, inherited) ],
		[ _('Resource profile override'), text(config.resource_control, inherited) ],
		[ _('Log level override'), text(config.log_level, inherited) ],
		[ _('Statistics override'), config.statistics_enabled === null || config.statistics_enabled === undefined ? inherited : (config.statistics_enabled ? _('Enabled') : _('Disabled')) ],
		[ _('Update status'), updateState(updater) ]
	];

	return E('div', { class: 'cbi-section' }, [
		E('h3', {}, _('Runtime status')),
		E('table', { class: 'table' }, rows.map(function(row) {
			return E('tr', { class: 'tr' }, [
				E('td', { class: 'td left', width: '35%' }, [ row[0] ]),
				E('td', { class: 'td left' }, [ row[1] ])
			]);
		}))
	]);
}

function renderControls(status, updater) {
	const service = status.service || {};
	const config = status.config || {};
	const port = config.effective_listen_port || config.listen_port || 25500;
	return E('div', { class: 'cbi-section' }, [
		E('h3', {}, _('Service controls')),
		E('p', {}, _('Runtime state and start-at-boot are controlled independently.')),
		E('div', { class: 'cbi-page-actions' }, [
			actionButton(_('Start'), 'start', status, updater, true), ' ',
			actionButton(_('Stop'), 'stop', status, updater, false), ' ',
			actionButton(_('Restart'), 'restart', status, updater, false), ' ',
			actionButton(service.enabled ? _('Disable start at boot') : _('Enable start at boot'), service.enabled ? 'disable' : 'enable', status, updater, false)
		]),
		E('h3', {}, _('Application pages')),
		E('p', {}, _('Links use the router address currently open in your browser and the effective runtime port reported by the service.')),
		E('div', { class: 'cbi-page-actions' }, [
			E('a', { class: 'btn cbi-button-action', href: endpoint(port, '/version'), target: '_blank', rel: 'noopener noreferrer' }, [ _('Version') ]), ' ',
			E('a', { class: 'btn cbi-button-action', href: endpoint(port, '/inspect'), target: '_blank', rel: 'noopener noreferrer' }, [ _('Inspect') ]), ' ',
			E('a', { class: 'btn cbi-button-action', href: endpoint(port, '/dashboard'), target: '_blank', rel: 'noopener noreferrer' }, [ _('Dashboard') ])
		])
	]);
}

return view.extend({
	load: function() {
		return Promise.all([ api.status(), api.updateStatus() ]);
	},

	render: function(data) {
		const status = data[0];
		const updater = data[1];
		const live = E('div', {}, [ renderStatus(status, updater), renderControls(status, updater) ]);

		poll.add(function() {
			return Promise.all([ api.status(), api.updateStatus() ]).then(function(fresh) {
				live.replaceChildren(renderStatus(fresh[0], fresh[1]), renderControls(fresh[0], fresh[1]));
			}).catch(api.notifyError);
		}, 5);

		return E('div', {}, [
			E('h2', {}, _('SubConverter-Extended - Overview')),
			live
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
