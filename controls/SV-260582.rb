control 'SV-260582' do
  title 'Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to Ubuntu 22.04 LTS performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) is installed by using the following command:

     $ dpkg -l | grep aide
     ii     aide     0.17.4-1     amd64     Advanced Intrusion Detection Environment - dynamic binary

If AIDE is not installed, ask the system administrator how file integrity checks are performed on the system.

If there is no application installed to perform integrity checks, this is a finding.'
  desc 'fix', 'Install the "aide" package:

     $ sudo apt install aide'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64311r953557_chk'
  tag severity: 'medium'
  tag gid: 'V-260582'
  tag rid: 'SV-260582r953559_rule'
  tag stig_id: 'UBTU-22-651010'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-64219r953558_fix'
  tag 'documentable'
  tag cci: ['CCI-002696', 'CCI-001744']
  tag nist: ['SI-6 a', 'CM-3 (5)']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  # if file_integrity_tool == 'aide'
  #   describe command('/usr/sbin/aide --check') do
  #     its('stdout') { should_not include "Couldn't open file" }
  #   end
  # end

  if file_integrity_tool == 'aide'
    describe command('dpkg -l | grep aide') do
      its('stdout') { should_not be_empty }
    end
  end

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
end
