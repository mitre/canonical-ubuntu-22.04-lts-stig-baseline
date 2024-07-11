control 'SV-260549' do
  title 'Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Verify that Ubuntu 22.04 LTS utilizes the "pam_faillock" module by using the following command: 
 
     $ grep faillock /etc/pam.d/common-auth 
 
auth     [default=die]  pam_faillock.so authfail 
auth     sufficient     pam_faillock.so authsucc 
 
If the "pam_faillock.so" module is not present in the "/etc/pam.d/common-auth" file, this is a finding. 
 
Verify the "pam_faillock" module is configured to use the following options: 
 
     $ sudo grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf 
     audit 
     silent 
     deny = 3 
     fail_interval = 900 
     unlock_time = 0 
 
If "audit" is commented out, or is missing, this is a finding.

If "silent" is commented out, or is missing, this is a finding.

If "deny" is set to a value greater than "3", is commented out, or is missing, this is a finding.
 
If "fail_interval" is set to a value greater than "900", is commented out, or is missing, this is a finding.
 
If "unlock_time" is not set to "0", is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to utilize the "pam_faillock" module.  
 
Add or modify the following lines in the "/etc/pam.d/common-auth" file, below the "auth" definition for "pam_unix.so":  
 
auth     [default=die]  pam_faillock.so authfail 
auth     sufficient          pam_faillock.so authsucc 
 
Configure the "pam_faillock" module to use the following options. 
 
Add or modify the following lines in the "/etc/security/faillock.conf" file: 
 
audit 
silent 
deny = 3 
fail_interval = 900 
unlock_time = 0'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64278r953458_chk'
  tag severity: 'low'
  tag gid: 'V-260549'
  tag rid: 'SV-260549r953460_rule'
  tag stig_id: 'UBTU-22-411045'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-64186r953459_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  lockout_time = input('lockout_time')

  describe parse_config_file('/etc/security/faillock.conf') do
    its('unlock_time') { should cmp lockout_time }
  end
end
