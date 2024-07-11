control 'SV-260648' do
  title 'Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.  
  
Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'Verify Ubuntu 22.04 LTS audits the execution of privilege functions by auditing the "execve" system call by using the following command:  
  
     $ sudo auditctl -l | grep execve 
     -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
     -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv 
     -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
     -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv 
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of all privileged functions.  
  
Add or modify the following lines in the "/etc/audit/rules.d/stig.rules" file:  
  
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv 
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv 
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv 
 
To reload the rules file, issue the following command:  
  
     $ sudo augenrules --load 
 
Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127']
  tag gid: 'V-260648'
  tag rid: 'SV-260648r953757_rule'
  tag stig_id: 'UBTU-22-654230'
  tag fix_id: 'F-64285r953756_fix'
  tag cci: ['CCI-002233', 'CCI-002234']
  tag nist: ['AC-6 (8)', 'AC-6 (9)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_syscalls = ['execve']

  describe 'Syscall' do
    audit_syscalls.each do |audit_syscall|
      it "#{audit_syscall} is audited properly" do
        audit_rule = auditd.syscall(audit_syscall)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        if os.arch.match(/64/)
          expect(audit_rule.arch.uniq).to include('b32', 'b64')
        else
          expect(audit_rule.arch.uniq).to cmp 'b32'
        end
        expect(audit_rule.fields.flatten).to include('uid!=euid', 'gid!=egid', 'euid=0', 'egid=0')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
