control 'SV-260568' do
  title 'Ubuntu 22.04 LTS must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify Ubuntu 22.04 LTS prevents passwords from being reused for a minimum of five generations by using the following command: 
 
     $ grep -i remember /etc/pam.d/common-password 
     password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5 rounds=5000 
 
If "remember" is not greater than or equal to "5", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to prevent passwords from being reused for a minimum of five generations. 
 
Add or modify the following line in the "/etc/pam.d/common-password" file: 
 
password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5 rounds=5000'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64297r953515_chk'
  tag severity: 'medium'
  tag gid: 'V-260568'
  tag rid: 'SV-260568r954000_rule'
  tag stig_id: 'UBTU-22-611050'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-64205r953516_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe file('/etc/pam.d/common-password') do
      it { should exist }
    end

    describe command("grep -i remember /etc/pam.d/common-password | sed 's/.*remember=\\([^ ]*\\).*/\\1/'") do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should cmp >= 5 }
    end
  end
end
