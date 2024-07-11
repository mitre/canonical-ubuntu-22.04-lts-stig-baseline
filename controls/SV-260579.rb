control 'SV-260579' do
  title 'Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that "use_mappers" is set to "pwent" in "/etc/pam_pkcs11/pam_pkcs11.conf" file by using the following command:  
  
     $ grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf 
     use_mappers = pwent 
  
If "use_mappers" does not contain "pwent", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Set "use_mappers=pwent" in "/etc/pam_pkcs11/pam_pkcs11.conf" or, if there is already a comma-separated list of mappers, add it to the list, separated by comma, and before the null mapper.  
  
If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-260579'
  tag rid: 'SV-260579r953550_rule'
  tag stig_id: 'UBTU-22-612040'
  tag fix_id: 'F-64216r953549_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/etc/sssd/sssd.conf') do
    it { should exist }
    its('content') { should match(/^\s*\[certmap.*\]\s*$/) }
  end
end
