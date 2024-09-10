control 'SV-260482' do
  title 'Ubuntu 22.04 LTS must not have the "rsh-server" package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Remote Shell (RSH) is a client/server application protocol that provides an unencrypted remote access service, which does not provide for the confidentiality and integrity of user passwords or the remote session. If users were allowed to login to a system using RSH, the privileged user passwords and communications could be compromised.

Removing the "rsh-server" package decreases the risk of accidental or intentional activation of the RSH service.'
  desc 'check', 'Verify the "rsh-server" package is not installed by using the following command:

     $ dpkg -l | grep rsh-server

If the "rsh-server" package is installed, this is a finding.'
  desc 'fix', 'Remove the "rsh-server" package by using the following command:

     $ sudo apt-get remove rsh-server'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000074-GPOS-00042']
  tag gid: 'V-260482'
  tag rid: 'SV-260482r953259_rule'
  tag stig_id: 'UBTU-22-215030'
  tag fix_id: 'F-64119r953258_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe package('rsh-server') do
    it { should_not be_installed }
  end
end
