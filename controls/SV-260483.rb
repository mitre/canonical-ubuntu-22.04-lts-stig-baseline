control 'SV-260483' do
  title 'Ubuntu 22.04 LTS must not have the "telnet" package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities are often overlooked and therefore, may remain unsecure. They increase the risk to the platform by providing additional attack vectors. 
 
Telnet is a client/server application protocol that provides an unencrypted remote access service, which does not provide for the confidentiality and integrity of user passwords or the remote session. If users were allowed to login to a system using Telnet, the privileged user passwords and communications could be compromised. 
 
Removing the "telnetd" package decreases the risk of accidental or intentional activation of the Telnet service.'
  desc 'check', 'Verify that the "telnetd" package is not installed on Ubuntu 22.04 LTS by using the following command:  
 
     $ dpkg -l | grep telnetd 
 
If the "telnetd" package is installed, this is a finding.'
  desc 'fix', 'Remove the "telnetd" package by using the following command:  
  
     $ sudo apt-get remove telnetd'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag gid: 'V-260483'
  tag rid: 'SV-260483r953262_rule'
  tag stig_id: 'UBTU-22-215035'
  tag fix_id: 'F-64120r953261_fix'
  tag cci: ['CCI-000381', 'CCI-000197']
  tag nist: ['CM-7 a', 'IA-5 (1) (c)']
  tag 'host'
  tag 'container'

  describe package('telnet-server') do
    it { should_not be_installed }
  end
end
