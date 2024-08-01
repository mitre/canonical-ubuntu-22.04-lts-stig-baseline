control 'SV-260650' do
  title 'Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the system is configured to run in FIPS mode by using the following command:  
  
     $ grep -i 1 /proc/sys/crypto/fips_enabled 
     1  
  
If a value of "1" is not returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to run in FIPS mode. Add "fips=1" to the kernel parameter during Ubuntu 22.04 LTS install.  
  
Enabling a FIPS mode on a pre-existing system involves a number of modifications to Ubuntu 22.04 LTS. Refer to the Ubuntu Pro security certification documentation for instructions.   
  
A subscription to the "Ubuntu Pro" plan is required to obtain the FIPS Kernel cryptographic modules and enable FIPS. 
 
Note: Ubuntu Pro security certification instructions can be found at: https://ubuntu.com/security/certifications/docs/fips-enablement'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64379r953761_chk'
  tag severity: 'high'
  tag gid: 'V-260650'
  tag rid: 'SV-260650r953763_rule'
  tag stig_id: 'UBTU-22-671010'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-64287r953762_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command('grep -i 1 /proc/sys/crypto/fips_enabled') do
    its('stdout') { should match('1') }
  end
end
