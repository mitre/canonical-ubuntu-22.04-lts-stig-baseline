control 'SV-260565' do
  title 'Ubuntu 22.04 LTS must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.  
  
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the pwquality configuration file enforces a minimum 15-character password length by using the following command: 
 
     $ grep -i minlen /etc/security/pwquality.conf 
     minlen = 15 
 
If "minlen" is not "15" or higher, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce a minimum 15-character password length.  
  
Add or modify the following line in the "/etc/security/pwquality.conf" file: 
 
minlen = 15'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: 'V-260565'
  tag rid: 'SV-260565r954001_rule'
  tag stig_id: 'UBTU-22-611035'
  tag fix_id: 'F-64202r953507_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minlen.to_i') { should cmp >= input('pass_min_len') }
  end
end
