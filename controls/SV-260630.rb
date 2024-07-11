control 'SV-260630' do
  title 'Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.  
  
To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify Ubuntu 22.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd" by using the following command: 
 
     $ sudo auditctl -l | grep opasswd 
     -w /etc/security/opasswd -p wa -k usergroup_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd". 
 
Add or modify the following line to "/etc/audit/rules.d/stig.rules": 
 
-w /etc/security/opasswd -p wa -k usergroup_modification 
 
To reload the rules file, issue the following command: 
 
     $ sudo augenrules --load 
 
Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207']
  tag gid: 'V-260630'
  tag rid: 'SV-260630r953703_rule'
  tag stig_id: 'UBTU-22-654140'
  tag fix_id: 'F-64267r953702_fix'
  tag cci: ['CCI-000169', 'CCI-000018', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002132', 'CCI-002884']
  tag nist: ['AU-12 a', 'AC-2 (4)', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/etc/security/opasswd'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
