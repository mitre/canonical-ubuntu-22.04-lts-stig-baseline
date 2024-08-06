control 'SV-260502' do
  title 'Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.  
  
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal directories are group-owned by "systemd-journal" by using the following command: 
 
     $ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \\; 
     /run/log/journal systemd-journal 
     /var/log/journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce systemd-journal 
 
If any output returned is not group-owned by "systemd-journal", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to set the appropriate group-ownership to the directories used by the systemd journal: 
 
Add or modify the following lines in the "/usr/lib/tmpfiles.d/systemd.conf" file: 
 
z /run/log/journal 2640 root systemd-journal - - 
z /var/log/journal 2640 root systemd-journal - - 
 
Restart the system for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64231r953317_chk'
  tag severity: 'medium'
  tag gid: 'V-260502'
  tag rid: 'SV-260502r953319_rule'
  tag stig_id: 'UBTU-22-232085'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64139r953318_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/run/log/journal') do
    it { should exist }
    its('group') { should eq 'systemd-journal' }
  end

  describe directory('/var/log/journal') do
    it { should exist }
    its('group') { should eq 'systemd-journal' }
  end
end
