control 'SV-260625' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
  
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify if Ubuntu 22.04 LTS generates audit records upon successful/unsuccessful attempts to use the "umount" command by using the following command:  
  
     $ sudo auditctl -l | grep /usr/bin/umount 
     -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-umount  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" command.   
  
Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:  
  
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-umount  
  
To reload the rules file, issue the following command:  
  
     $ sudo augenrules --load 
 
Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-260625'
  tag rid: 'SV-260625r953688_rule'
  tag stig_id: 'UBTU-22-654115'
  tag fix_id: 'F-64262r953687_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  audit_command = '/usr/bin/umount'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
