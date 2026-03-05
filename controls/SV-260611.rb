control 'SV-260611' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to audit the execution of the partition management program "fdisk" by using the following command:

     $ sudo auditctl -l | grep fdisk
     -w /usr/sbin/fdisk -p x -k fdisk

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of the partition management program "fdisk".

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /usr/sbin/fdisk -p x -k fdisk

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  tag check_id: 'C-64340r953644_chk'
  tag severity: 'medium'
  tag gid: 'V-260611'
  tag rid: 'SV-260611r991586_rule'
  tag stig_id: 'UBTU-22-654045'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-64248r953645_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/usr/sbin/fdisk'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('x')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
