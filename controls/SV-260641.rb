control 'SV-260641' do
  title 'Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
  
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify Ubuntu 22.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/log/btmp" file by using the following command:  
  
     $ sudo auditctl -l | grep '/var/log/btmp'  
     -w /var/log/btmp -p wa -k logins  
  
If the command does not return a line matching the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.)
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the "/var/log/btmp file".  
  
Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:  
  
-w /var/log/btmp -p wa -k logins  
   
To reload the rules file, issue the following command:  
  
     $ sudo augenrules --load 
 
Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64370r953734_chk'
  tag severity: 'medium'
  tag gid: 'V-260641'
  tag rid: 'SV-260641r953736_rule'
  tag stig_id: 'UBTU-22-654195'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-64278r953735_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    @audit_file = '/var/log/btmp'

    audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
    if audit_lines_exist
      describe auditd.file(@audit_file) do
        its('permissions') { should_not cmp [] }
        its('action') { should_not include 'never' }
      end

      @perms = auditd.file(@audit_file).permissions

      @perms.each do |perm|
        describe perm do
          it { should include 'w' }
          it { should include 'a' }
        end
      end
    else
      describe('Audit line(s) for ' + @audit_file + ' exist') do
        subject { audit_lines_exist }
        it { should be true }
      end
    end
  end
end
