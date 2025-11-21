control 'SV-260644' do
  title 'Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
  
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful modifications to the "faillog" file by using the following command: 
  
     $ sudo auditctl -l | grep faillog  
     -w /var/log/faillog -p wa -k logins  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful modifications to the "faillog" file.   
  
Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:  
  
-w /var/log/faillog -p wa -k logins  
    
To reload the rules file, issue the following command:  
  
     $ sudo augenrules --load 
 
Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64373r953743_chk'
  tag severity: 'medium'
  tag gid: 'V-260644'
  tag rid: 'SV-260644r953745_rule'
  tag stig_id: 'UBTU-22-654210'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-64281r953744_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000064-GPOS-00033']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/var/log/faillog'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
