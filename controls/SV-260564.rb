control 'SV-260564' do
  title 'Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords.'
  desc 'If Ubuntu 22.04 LTS allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify Ubuntu 22.04 LTS prevents the use of dictionary words for passwords by using the following command: 
 
     $ grep -i dictcheck /etc/security/pwquality.conf 
     dictcheck = 1  
  
If "dictcheck" is not set to "1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to prevent the use of dictionary words for passwords. 
  
Add or modify the following line in the "/etc/security/pwquality.conf" file: 
  
dictcheck = 1'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-260564'
  tag rid: 'SV-260564r953505_rule'
  tag stig_id: 'UBTU-22-611030'
  tag fix_id: 'F-64201r953504_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('dictcheck') { should eq '1' }
  end
end
