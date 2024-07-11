control 'SV-260550' do
  title 'Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces a delay of at least four seconds between logon prompts following a failed logon attempt by using the following command:  
  
     $ grep pam_faildelay /etc/pam.d/common-auth 
     auth     required     pam_faildelay.so     delay=4000000  
  
If "delay" is not set to "4000000" or greater, the line is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce a delay of at least four seconds between logon prompts following a failed logon attempt. 
 
Add or modify the following line in the "/etc/pam.d/common-auth" file: 
 
auth     required     pam_faildelay.so     delay=4000000'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-260550'
  tag rid: 'SV-260550r953463_rule'
  tag stig_id: 'UBTU-22-412010'
  tag fix_id: 'F-64187r953462_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('FAIL_DELAY.to_i') { should cmp >= input('login_prompt_delay') }
  end
end
