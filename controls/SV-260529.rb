control 'SV-260529' do
  title 'Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.'
  desc "The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack when the SSH client requests forwarding.  A system administrator may have a stance in which they want to protect clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a ''no'' setting.  
  
X11 forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the user's X11 authorization database) can access the local X11 display through the forwarded connection. An attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also enabled.  
  
If X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the system's needs."
  desc 'check', %q(Verify that X11 forwarding is disabled by using the following command:  
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11forwarding' 
     /etc/ssh/sshd_config:X11Forwarding no 
  
If "X11Forwarding" is set to "yes" and is not documented with the information system security officer (ISSO) as an operational requirement, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to disable X11 forwarding.  
 
Add or modify the following line in the "/etc/ssh/sshd_config" file: 
 
X11Forwarding no  
  
Restart the SSH daemon for the changes to take effect:  
  
     $ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-260529'
  tag rid: 'SV-260529r953400_rule'
  tag stig_id: 'UBTU-22-255040'
  tag fix_id: 'F-64166r953399_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  if input('x11_forwarding_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe sshd_config do
      its('X11Forwarding') { should cmp 'no' }
    end
  end
end
