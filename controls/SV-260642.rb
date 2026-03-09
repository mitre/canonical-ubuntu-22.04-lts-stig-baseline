control 'SV-260642' do
  title 'Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify Ubuntu 22.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/log/wtmp" file by using the following command:

     $ sudo auditctl -l | grep '/var/log/wtmp'
     -w /var/log/wtmp -p wa -k logins

If the command does not return a line matching the example or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.)
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the "/var/log/wtmp" file.

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/wtmp -p wa -k logins

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  tag check_id: 'C-64371r953737_chk'
  tag severity: 'medium'
  tag gid: 'V-260642'
  tag rid: 'SV-260642r991581_rule'
  tag stig_id: 'UBTU-22-654200'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-64279r953738_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_file = '/var/log/wtmp'

  if auditd.lines.nil? || auditd.lines.empty?
    describe 'Audit rules' do
      skip 'No audit rules loaded or auditd not configured'
    end
  else
    describe auditd.file(audit_file) do
      it { should exist }
      its('action') { should_not include 'never' }
      its('permissions.flatten') { should include('w', 'a') }
    end
  end
end
