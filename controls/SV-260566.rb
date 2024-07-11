control 'SV-260566' do
  title 'Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.  
  
The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.  
  
If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least eight characters.'
  desc 'check', 'Verify Ubuntu 22.04 LTS requires the change of at least eight characters when passwords are changed by using the following command: 
  
     $ grep -i difok /etc/security/pwquality.conf 
     difok = 8  
  
If "difok" is less than "8", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to require the change of at least eight characters when passwords are changed.  
  
Add or modify the following line in the "/etc/security/pwquality.conf" file: 
 
difok = 8'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64295r953509_chk'
  tag severity: 'medium'
  tag gid: 'V-260566'
  tag rid: 'SV-260566r953998_rule'
  tag stig_id: 'UBTU-22-611040'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-64203r953510_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
  tag 'host'
  tag 'container'

  setting = 'difok'
  expected_value = input('difok')

  pattern = /^[^#]*#{setting}\s*=\s*(?<value>\d+)$/
  setting_check = command("grep #{setting} /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf").stdout.strip.scan(pattern).flatten

  describe 'Password settings for the root account' do
    it 'should be set' do
      expect(setting_check).to_not be_empty, "'#{setting}' not found (or commented out) in conf file(s)"
    end
    it 'should only be set once' do
      expect(setting_check.length).to eq(1), "'#{setting}' set more than once in conf file(s)"
    end
    it "should be set to be >= #{expected_value}" do
      expect(setting_check.first.to_i).to be >= expected_value, "'#{setting}' set to less than '#{expected_value}' in conf file(s)"
    end
  end
end
