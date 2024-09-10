control 'SV-260468' do
  title 'Ubuntu 22.04 LTS must deploy an Endpoint Security Solution.'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Verify that an Endpoint Security Solution has been deployed on the operating system.

If there is not an Endpoint Security Solution deployed, this is a finding.'
  desc 'fix', 'Install an Endpoint Security Solution that can provide a continuous mechanism to monitor the state of system components with regard to flaw remediation and threat prevention.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag gid: 'V-260468'
  tag rid: 'SV-260468r954041_rule'
  tag stig_id: 'UBTU-22-211010'
  tag fix_id: 'F-64105r953216_fix'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  if input('skip_endpoint_security_tool')
    impact 0.0
    describe 'Implementing the Endpoint Security for Linux Threat Prevention tool is not applicable by agreement with  the approval authority of the organization.' do
      skip 'Implementing the Endpoint Security for Linux Threat Prevention tool is not applicable by agreement with  the approval authority of the organization.'
    end
  else
    linux_threat_prevention_package = input('linux_threat_prevention_package')
    linux_threat_prevention_service = input('linux_threat_prevention_service')
    describe package(linux_threat_prevention_package) do
      it { should be_installed }
    end

    describe processes(linux_threat_prevention_service) do
      it { should exist }
    end
  end
end
