control 'SV-260614' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify if Ubuntu 22.04 LTS is configured to audit the execution of the module management program "modprobe" with the following command:

     $ sudo auditctl -l | grep /sbin/modprobe
     -w /sbin/modprobe -p x -k modules

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of the module management program "modprobe".

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /sbin/modprobe -p x -k modules

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  tag check_id: 'C-64343r953653_chk'
  tag severity: 'medium'
  tag gid: 'V-260614'
  tag rid: 'SV-260614r991586_rule'
  tag stig_id: 'UBTU-22-654060'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-64251r953654_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_file = '/sbin/modprobe'

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
