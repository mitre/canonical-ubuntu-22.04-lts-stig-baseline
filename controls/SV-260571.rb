control 'SV-260571' do
  title 'Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', "Verify all accounts on the system to have a password by using the following command: 
 
     $ sudo awk -F: '!$2 {print $1}' /etc/shadow 
 
If the command returns any results, this is a finding."
  desc 'fix', 'Configure all accounts on the system to have a password or lock the account by using the following commands: 
 
Set the account password: 
 
     $ sudo passwd <username> 
 
Or lock the account: 
 
     $ sudo passwd -l <username>'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64300r953524_chk'
  tag severity: 'high'
  tag gid: 'V-260571'
  tag rid: 'SV-260571r953526_rule'
  tag stig_id: 'UBTU-22-611065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64208r953525_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  users_with_blank_passwords = shadow.where { password.nil? || password.empty? }.users - input('users_allowed_blank_passwords')

  describe 'All users' do
    it 'should have a password set' do
      fail_msg = "Users with blank passwords:\n\t- #{users_with_blank_passwords.join("\n\t- ")}"
      expect(users_with_blank_passwords).to be_empty, fail_msg
    end
  end
end
