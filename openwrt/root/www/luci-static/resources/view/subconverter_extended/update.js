'use strict';
'require view';
'require form';
'require poll';
'require ui';
'require subconverter_extended.api as api';

function text(value, fallback) {
	return value === undefined || value === null || value === '' ? fallback : String(value);
}

function field(status, name) {
	if (status && status[name] !== undefined && status[name] !== null)
		return status[name];
	if (status && status.info && status.info[name] !== undefined && status.info[name] !== null)
		return status.info[name];
	return null;
}

function formatTime(value) {
	const epoch = Number(value);
	if (!Number.isFinite(epoch) || epoch <= 0)
		return _('Not recorded');
	return new Date(epoch * 1000).toLocaleString();
}

function stateLabel(state) {
	const labels = {
		idle: _('Idle'), checking: _('Checking'), available: _('Update available'),
		up_to_date: _('Up to date'), downloading: _('Downloading'), verifying: _('Verifying'),
		verified: _('Verified'),
		installing: _('Installing'), validating: _('Validating'), completed: _('Completed'),
		rolling_back: _('Rolling back'), rolled_back: _('Rolled back'), failed: _('Failed'),
		success: _('Completed'), error: _('Failed'), queued: _('Queued'), preparing: _('Preparing'),
		stopping: _('Stopping service'), recovering: _('Recovering'), recovered: _('Recovered'),
		recovery_failed: _('Recovery failed'), newer_local: _('Local build is newer'),
		configuration_error: _('Installed; configuration reload failed'),
		updater_error: _('Installed; updater reload failed'),
		unavailable: _('Unavailable')
	};
	return labels[state] || text(state, _('Not checked'));
}

function busy(status) {
	return [ 'queued', 'preparing', 'checking', 'downloading', 'verified', 'stopping',
		'installing', 'validating', 'rolling_back', 'recovering' ].indexOf(status && status.state) >= 0;
}

function startAction(action, panel, button) {
	button.disabled = true;
	return api.updateAction(action).then(function() {
		ui.addNotification(null, E('p', {}, _('Update task accepted. Progress will refresh automatically.')), 'info');
		window.setTimeout(function() { window.location.reload(); }, 500);
	}).catch(function(error) {
		button.disabled = false;
		api.notifyError(error);
	});
}

function confirmAction(title, message, action, panel, button) {
	ui.showModal(title, [
		E('p', {}, message),
		E('div', { class: 'right' }, [
			E('button', { class: 'btn', click: ui.hideModal }, _('Cancel')), ' ',
			E('button', {
				class: 'btn cbi-button-positive',
				click: function() {
					ui.hideModal();
					return startAction(action, panel, button);
				}
			}, title)
		])
	]);
}

function renderUpdateStatus(status, panel) {
	const isBusy = busy(status);
	const available = field(status, 'available') === true;
	const error = field(status, 'error');
	const message = field(status, 'message');
	const rows = [
		[ _('State'), stateLabel(status && status.state) ],
		[ _('Current version'), text(field(status, 'current_version'), _('Unavailable')) ],
		[ _('Latest version'), text(field(status, 'latest_version'), _('Not checked')) ],
		[ _('Architecture'), text(field(status, 'architecture'), _('Unavailable')) ],
		[ _('Metadata source'), text(field(status, 'api_source') || field(status, 'source'), _('Not checked')) ],
		[ _('Download source'), text(field(status, 'download_source'), _('Not selected')) ],
		[ _('Progress'), String(Number(field(status, 'progress')) || 0) + '%' ],
		[ _('Status updated'), formatTime(field(status, 'updated_at')) ],
		[ _('Last successful version'), text(field(status, 'last_good_version'), _('Not recorded')) ],
		[ _('Last successful update'), formatTime(field(status, 'last_good_at')) ],
		[ _('Last failed version'), text(field(status, 'last_failure_version'), _('Not recorded')) ],
		[ _('Last failed update'), formatTime(field(status, 'last_failure_at')) ]
	];

	const check = E('button', { class: 'btn cbi-button-action', disabled: isBusy ? '' : null }, [ _('Check for updates') ]);
	check.addEventListener('click', function() { return startAction('check', panel, check); });

	const apply = E('button', { class: 'btn cbi-button-positive', disabled: isBusy || !available ? '' : null }, [ _('Install update') ]);
	apply.addEventListener('click', function() {
		confirmAction(_('Install update'), _('The service and LuCI integration will be replaced as one package. Persistent configuration is preserved, and failed validation triggers rollback.'), 'apply', panel, apply);
	});

	const rollback = E('button', {
		class: 'btn cbi-button-negative',
		disabled: isBusy || field(status, 'rollback_available') !== true ? '' : null
	}, [ _('Roll back') ]);
	rollback.addEventListener('click', function() {
		confirmAction(_('Roll back'), _('Restore the last retained package and validate the service again. Current persistent configuration is not deleted.'), 'rollback', panel, rollback);
	});

	const notices = [];
	if (message)
		notices.push(E('div', { class: 'alert-message notice' }, [ String(message) ]));
	if (error)
		notices.push(E('div', { class: 'alert-message warning' }, api.detailNode(_('Update error'), error)));

	return E('div', { class: 'cbi-section' }, [
		E('h3', {}, _('Update status')),
		E('table', { class: 'table' }, rows.map(function(row) {
			return E('tr', { class: 'tr' }, [
				E('td', { class: 'td left', width: '35%' }, [ row[0] ]),
				E('td', { class: 'td left' }, [ row[1] ])
			]);
		})),
		...notices,
		E('div', { class: 'cbi-page-actions' }, [ check, ' ', apply, ' ', rollback ])
	]);
}

function validateClock(sectionId, value) {
	if (!/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(value || ''))
		return _('Enter a time in 24-hour HH:MM format.');
	return true;
}

function updateForm() {
	let m, s, o;
	m = new form.Map('subconverter-extended', _('Automatic update settings'),
		_('The trusted source is always this project\'s latest stable GitHub Release. Auto mode tries the built-in public proxy pool before direct GitHub access.'));

	s = m.section(form.TypedSection, 'update', _('Schedule and source'));
	s.anonymous = true;
	s.addremove = false;

	o = s.option(form.Flag, 'enabled', _('Enable the update system'));
	o.default = '1';
	o.rmempty = false;

	o = s.option(form.Flag, 'auto_check', _('Check automatically'));
	o.default = '1';
	o.rmempty = false;
	o.depends('enabled', '1');

	o = s.option(form.Flag, 'auto_install', _('Install automatically'),
		_('When disabled, automatic checks only report that an update is available.'));
	o.default = '0';
	o.rmempty = false;
	o.depends('enabled', '1');

	o = s.option(form.ListValue, 'check_interval', _('Check interval'));
	o.value('21600', _('Every 6 hours'));
	o.value('43200', _('Every 12 hours'));
	o.value('86400', _('Daily'));
	o.value('604800', _('Weekly'));
	o.default = '86400';
	o.rmempty = false;
	o.depends('auto_check', '1');

	o = s.option(form.Value, 'install_start', _('Installation window starts'));
	o.default = '03:00';
	o.rmempty = false;
	o.validate = validateClock;
	o.depends('auto_install', '1');

	o = s.option(form.Value, 'install_end', _('Installation window ends'));
	o.default = '05:00';
	o.rmempty = false;
	o.validate = validateClock;
	o.depends('auto_install', '1');

	o = s.option(form.ListValue, 'proxy_mode', _('Proxy mode'));
	o.value('auto', _('Automatic proxy pool'));
	o.value('gh-proxy', 'gh-proxy.com');
	o.value('yylx', 'git.yylx.win');
	o.value('direct', _('Direct GitHub'));
	o.default = 'auto';
	o.rmempty = false;

	return m;
}

return view.extend({
	load: function() {
		return api.updateStatus();
	},

	render: function(status) {
		const initiallyBusy = busy(status);
		const panel = E('div');
		panel.appendChild(renderUpdateStatus(status, panel));
		const formMap = updateForm();
		if (busy(status))
			formMap.readonly = true;

		poll.add(function() {
			return api.updateStatus().then(function(fresh) {
				panel.replaceChildren(renderUpdateStatus(fresh, panel));
				if (initiallyBusy && !busy(fresh))
					window.location.reload();
			}).catch(api.notifyError);
		}, 3);

		return Promise.resolve(formMap.render()).then(function(formNode) {
			return E('div', {}, [
				E('h2', {}, _('SubConverter-Extended - Software update')),
				E('p', {}, _('Release metadata and packages may be fetched through trusted public reverse proxies. Repository identity, stable version selection and exact architecture matching remain fixed by the updater.')),
				panel,
				formNode
			]);
		});
	},

	handleSave: function(ev) {
		return api.updateStatus().then(function(status) {
			if (busy(status)) {
				const error = new Error(_('Update transaction is active.'));
				error.detail = _('Wait for it to finish before changing automatic update settings.');
				throw error;
			}
			return this.super('handleSave', [ ev ]);
		}.bind(this));
	}
});
