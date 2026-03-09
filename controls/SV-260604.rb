control 'SV-260604' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "apparmor_parser" command by using the following command:

     $ sudo auditctl -l | grep apparmor_parser
     -a always,exit -S all -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "apparmor_parser" command.

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  tag check_id: 'C-64333r953623_chk'
  tag severity: 'medium'
  tag gid: 'V-260604'
  tag rid: 'SV-260604r958446_rule'
  tag stig_id: 'UBTU-22-654010'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-64241r953624_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_file = '/sbin/apparmor_parser'

  if auditd.lines.nil? || auditd.lines.empty?
    describe 'Audit rules' do
      skip 'No audit rules loaded or auditd not configured'
    end
  else
    describe auditd.file(audit_file) do
      it { should exist }
      its('action') { should_not include 'never' }
      its('permissions.flatten') { should include 'x' }
    end
  end
end
