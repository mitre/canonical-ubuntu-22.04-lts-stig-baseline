control 'SV-260487' do
  title 'Ubuntu 22.04 LTS library files must have mode "755" or less permissive.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.  
  
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" have mode "755" or less permissive by using the following command:  
  
     $ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \; 
 
If any files are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the library files to be protected from unauthorized access. Run the following command:  
 
     $ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-260487'
  tag rid: 'SV-260487r953274_rule'
  tag stig_id: 'UBTU-22-232020'
  tag fix_id: 'F-64124r953273_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_libraries').join(' ')} -perm /0022 -type f -exec ls -d {} \\;").stdout.split("\n")

  describe 'System libraries' do
    it "should have mode '0755' or less permissive" do
      expect(failing_files).to be_empty, "Files with excessive permissions:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
