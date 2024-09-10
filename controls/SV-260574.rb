control 'SV-260574' do
  title 'Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the "opensc-pcks11" package is installed on the system by using the following command:

     $ dpkg -l | grep opensc-pkcs11
     ii     opensc-pkcs11:amd64     0.22.0-1Ubuntu2     amd64     Smart card utilities with support for PKCS#15 compatible cards

If the "opensc-pcks11" package is not installed, this is a finding.'
  desc 'fix', 'Install the "opensc-pkcs11" package by using the following command:

     $ sudo apt-get install opensc-pkcs11'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64303r953533_chk'
  tag severity: 'medium'
  tag gid: 'V-260574'
  tag rid: 'SV-260574r953535_rule'
  tag stig_id: 'UBTU-22-612015'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-64211r953534_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001953']
  tag nist: ['IA-2 (11)', 'IA-2 (12)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('smart_card_enabled')
    describe package('opensc') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable.'
    end
  end
end
