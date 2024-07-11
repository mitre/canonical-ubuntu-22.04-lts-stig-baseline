control 'SV-260572' do
  title 'Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', %q(Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS 140-3 approved cryptographic hashing algorithm by using the following command:  
  
     $ grep -i '^\s*encrypt_method' /etc/login.defs 
     ENCRYPT_METHOD SHA512  
  
If "ENCRYPT_METHOD" does not equal SHA512 or greater, is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to encrypt all stored passwords.   
  
Add or modify the following line in the "/etc/login.defs" file: 
  
ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-260572'
  tag rid: 'SV-260572r953529_rule'
  tag stig_id: 'UBTU-22-611070'
  tag fix_id: 'F-64209r953528_fix'
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
  tag 'host'
  tag 'container'

  weak_pw_hash_users = inspec.shadow.where { password !~ /^[*!]{1,2}.*$|^\$6\$.*$|^$/ }.users

  describe 'All stored passwords' do
    it 'should only be hashed with the SHA512 algorithm' do
      message = "Users without SHA512 hashes:\n\t- #{weak_pw_hash_users.join("\n\t- ")}"
      expect(weak_pw_hash_users).to be_empty, message
    end
  end
end
