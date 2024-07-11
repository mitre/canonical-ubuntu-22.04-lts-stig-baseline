control 'SV-260516' do
  title 'Ubuntu 22.04 LTS must have an application firewall enabled.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Verify the Uncomplicated Firewall (ufw) is enabled on the system with the following command:  
  
     $ systemctl status ufw.service | grep -i "active:" 
     Active: active (exited) since Thu 2022-12-25 00:00:01 NZTD; 365 days 11h ago 
  
If "ufw.service" is "inactive", this is a finding.  
  
If the ufw is not installed, ask the system administrator if another application firewall is installed. If no application firewall is installed, this is a finding.'
  desc 'fix', 'Enable and start the ufw by using the following command:  
  
     $ sudo systemctl enable ufw.service --now'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag gid: 'V-260516'
  tag rid: 'SV-260516r953361_rule'
  tag stig_id: 'UBTU-22-251020'
  tag fix_id: 'F-64153r953360_fix'
  tag cci: ['CCI-002314', 'CCI-000366', 'CCI-000382', 'CCI-002322']
  tag nist: ['AC-17 (1)', 'CM-6 b', 'CM-7 b', 'AC-17 (9)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  alternate_firewall_tool = input('alternate_firewall_tool')

  if alternate_firewall_tool != ''
    describe package(alternate_firewall_tool) do
      it { should be_installed }
    end
  else
    describe package('firewalld') do
      it { should be_installed }
    end
  end
end
