control 'SV-260526' do
  title 'Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH.'
  desc 'Failure to restrict system access to authenticated users negatively impacts Ubuntu 22.04 LTS security.'
  desc 'check', %q(Verify that unattended or automatic login via SSH is disabled by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))' 
     /etc/ssh/sshd_config:PermitEmptyPasswords no 
     /etc/ssh/sshd_config:PermitUserEnvironment no 
 
If "PermitEmptyPasswords" and "PermitUserEnvironment" are not set to "no", are commented out, are missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to not allow unattended or automatic login to the system.  
  
Add or modify the following lines in the "/etc/ssh/sshd_config" file:  
  
PermitEmptyPasswords no 
PermitUserEnvironment no 
  
Restart the SSH daemon for the changes to take effect: 
  
     $ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-260526'
  tag rid: 'SV-260526r953391_rule'
  tag stig_id: 'UBTU-22-255025'
  tag fix_id: 'F-64163r953390_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  describe sshd_config do
    its('PermitUserEnvironment') { should cmp 'no' }
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end
