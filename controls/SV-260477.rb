control 'SV-260477' do
  title 'Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify APT is configured to remove all software components after updated versions have been installed by using the following command:  
  
     $ grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades 
     Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"; 
     Unattended-Upgrade::Remove-Unused-Dependencies "true"; 
  
If "Unattended-Upgrade::Remove-Unused-Kernel-Packages" and "Unattended-Upgrade::Remove-Unused-Dependencies" are not set to "true", are commented out, or are missing, this is a finding.'
  desc 'fix', 'Configure APT to remove all software components after updated versions have been installed.  
  
Add or modify the following lines in the "/etc/apt/apt.conf.d/50-unattended-upgrades" file:  
 
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"; 
Unattended-Upgrade::Remove-Unused-Dependencies "true";'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64206r953242_chk'
  tag severity: 'medium'
  tag gid: 'V-260477'
  tag rid: 'SV-260477r953244_rule'
  tag stig_id: 'UBTU-22-214015'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-64114r953243_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']

  describe directory('/etc/apt/apt.conf.d') do
    it { should exist }
  end

  describe command('grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades').stdout.strip do
    it { should match(/^\s*([^\s]*::Remove-Unused-Dependencies)\s*\"true\"\s*;$/) }
    it { should match(/^\s*([^\s]*::Remove-Unused-Kernel-Packages)\s*\"true\"\s*;$/) }
  end
end
