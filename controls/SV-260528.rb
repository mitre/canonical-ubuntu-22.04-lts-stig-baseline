control 'SV-260528' do
  title 'Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element. 
 
Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.'
  desc 'check', %q(Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientaliveinterval' 
     /etc/ssh/sshd_config:ClientAliveInterval 600 
 
If "ClientAliveInterval" does not exist, is not set to a value of "600" or less, if conflicting results are returned, is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure the SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes. 
 
Note: This setting must be applied in conjunction with UBTU-22-255040 to function correctly. 
 
Add or modify the following line in the "/etc/ssh/sshd_config" file: 
 
ClientAliveInterval 600 
 
Restart the SSH daemon for the changes to take effect: 
 
     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000279-GPOS-00109', 'SRG-OS-000395-GPOS-00175']
  tag gid: 'V-260528'
  tag rid: 'SV-260528r953397_rule'
  tag stig_id: 'UBTU-22-255035'
  tag fix_id: 'F-64165r953396_fix'
  tag cci: ['CCI-001133', 'CCI-000879', 'CCI-002361', 'CCI-002891']
  tag nist: ['SC-10', 'MA-4 e', 'AC-12', 'MA-4 (7)']
  tag 'host'
  tag 'container-conditional'

  setting = 'ClientAliveInterval'
  gssapi_authentication = input('sshd_config_values')
  value = gssapi_authentication[setting]
  openssh_present = package('openssh-server').installed?

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !openssh_present)
  }

  if input('allow_container_openssh_server') == false
    describe 'In a container Environment' do
      it 'the OpenSSH Server should be installed only when allowed in a container environment' do
        expect(openssh_present).to eq(false), 'OpenSSH Server is installed but not approved for the container environment'
      end
    end
  else
    describe 'The OpenSSH Server configuration' do
      it "has the correct #{setting} configuration" do
        expect(sshd_config.params[setting.downcase]).to cmp(value), "The #{setting} setting in the SSHD config is not correct. Please ensure it set to '#{value}'."
      end
    end
  end
end
