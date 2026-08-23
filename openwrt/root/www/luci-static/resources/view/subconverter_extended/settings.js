'use strict';
'require view';
'require form';
'require subconverter_extended.api as api';

function busy(status) {
	return [ 'queued', 'preparing', 'checking', 'downloading', 'verified',
		'stopping', 'installing', 'validating', 'rolling_back', 'recovering' ]
		.indexOf(status && status.state) >= 0;
}

return view.extend({
	load: function() {
		return api.updateStatus();
	},

	render: function(status) {
		let m, s, o;

		m = new form.Map('subconverter-extended', _('SubConverter-Extended - Settings'),
			_('These OpenWrt settings override the corresponding values in pref.toml. Options not shown here remain managed by pref.toml. Restart the service after changing runtime settings.'));

		s = m.section(form.TypedSection, 'service', _('Basic settings'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.ListValue, 'config_file', _('Configuration file'),
			_('Select the persistent user configuration read by the service. Package defaults remain read-only under /opt/subconverter-extended.'));
		o.value('/etc/subconverter/pref.toml', '/etc/subconverter/pref.toml');
		o.value('/etc/subconverter/pref.yml', '/etc/subconverter/pref.yml');
		o.value('/etc/subconverter/pref.ini', '/etc/subconverter/pref.ini');
		o.default = '/etc/subconverter/pref.toml';
		o.rmempty = false;

		o = s.option(form.ListValue, 'listen_address', _('Listen address override'));
		o.value('', _('Inherit from pref.toml'));
		o.value('127.0.0.1', _('Loopback only (127.0.0.1)'));
		o.value('0.0.0.0', _('All IPv4 interfaces (0.0.0.0)'));
		o.value('::', _('All IPv6 and supported dual-stack interfaces (::)'));
		o.default = '';
		o.rmempty = true;

		o = s.option(form.Value, 'listen_port', _('Listen port override'));
		o.datatype = 'port';
		o.placeholder = '25500';
		o.rmempty = true;

		o = s.option(form.ListValue, 'security_profile', _('Security profile override'),
			_('Use public or strict when the service is reachable beyond a trusted LAN.'));
		o.value('', _('Inherit from pref.toml'));
		o.value('lan', _('LAN compatibility'));
		o.value('public', _('Public'));
		o.value('strict', _('Strict public'));
		o.default = '';
		o.rmempty = true;

		o = s.option(form.ListValue, 'allow_public_upload', _('Public upload override'),
			_('Only affects the public security profile. The strict profile always rejects public uploads.'));
		o.value('', _('Inherit from pref.toml'));
		o.value('0', _('Disabled'));
		o.value('1', _('Enabled'));
		o.default = '';
		o.rmempty = true;

		o = s.option(form.ListValue, 'resource_control', _('Resource control override'));
		o.value('', _('Inherit from pref.toml'));
		o.value('compat', _('Compatibility'));
		o.value('adaptive', _('Adaptive'));
		o.value('force_max', _('Hardware-aware maximum'));
		o.default = '';
		o.rmempty = true;

		o = s.option(form.ListValue, 'log_level', _('Log level override'));
		o.value('', _('Inherit from pref.toml'));
		o.value('info', _('Info'));
		o.value('warn', _('Warning'));
		o.value('error', _('Error'));
		o.value('fatal', _('Fatal'));
		o.value('verbose', _('Verbose'));
		o.value('debug', _('Debug'));
		o.default = '';
		o.rmempty = true;

		o = s.option(form.ListValue, 'statistics_enabled', _('Statistics override'));
		o.value('', _('Inherit from pref.toml'));
		o.value('0', _('Disabled'));
		o.value('1', _('Enabled'));
		o.default = '';
		o.rmempty = true;

		if (busy(status))
			m.readonly = true;

		return m.render();
	},

	handleSave: function(ev) {
		return api.updateStatus().then(function(status) {
			if (busy(status)) {
				const error = new Error(_('Update transaction is active.'));
				error.detail = _('Wait for it to finish before changing runtime settings.');
				throw error;
			}
			return this.super('handleSave', [ ev ]);
		}.bind(this));
	}
});
