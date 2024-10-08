control 'SV-260497' do
  title 'Ubuntu 22.04 LTS library directories must be owned by "root".'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.  
  
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library directories "/lib", "/lib64", and "/usr/lib" are owned by "root" by using the following command:  
  
     $ sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \; 
  
If any systemwide library directory is returned, this is a finding.)
  desc 'fix', "Configure the library files and their respective parent directories to be protected from unauthorized access. Run the following command:  
  
     $ sudo find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64226r953302_chk'
  tag severity: 'medium'
  tag gid: 'V-260497'
  tag rid: 'SV-260497r953304_rule'
  tag stig_id: 'UBTU-22-232060'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-64134r953303_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  non_root_owned_libs = input('system_libraries').reject { |lib| file(lib).owned_by?('root') }

  describe 'System libraries' do
    it 'should be owned by root' do
      fail_msg = "Libs not owned by root:\n\t- #{non_root_owned_libs.join("\n\t- ")}"
      expect(non_root_owned_libs).to be_empty, fail_msg
    end
  end
end
