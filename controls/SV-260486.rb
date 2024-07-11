control 'SV-260486' do
  title 'Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive.'
  desc 'If Ubuntu 22.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.  
  
This requirement applies to Ubuntu 22.04 LTS with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands contained in the following directories have mode "755" or less permissive by using the following command:  
  
     $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 
  
If any files are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure Ubuntu 22.04 LTS commands to be protected from unauthorized access. Run the following command:  
  
     $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64215r953269_chk'
  tag severity: 'medium'
  tag gid: 'V-260486'
  tag rid: 'SV-260486r953271_rule'
  tag stig_id: 'UBTU-22-232015'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-64123r953270_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
