control 'SV-274865' do
  title 'Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that authenticated certificates are mapped to the appropriate user group in the "/etc/sssd/sssd.conf" file with the following command:

$ grep -i ldap_user_certificate /etc/sssd/sssd.conf
ldap_user_certificate=userCertificate;binary'
  desc 'fix', 'Configure sssd to map authenticated certificates to the appropriate user group by adding the following line to the "/etc/sssd/sssd.conf" file:

ldap_user_certificate=userCertificate;binary'
  impact 0.5
  tag check_id: 'C-78966r1101729_chk'
  tag severity: 'medium'
  tag gid: 'V-274865'
  tag rid: 'SV-274865r1101731_rule'
  tag stig_id: 'UBTU-22-254030'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78871r1101730_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  sssd_conf = '/etc/sssd/sssd.conf'

  # Ensure the SSSD configuration file exists
  describe file(sssd_conf) do
    it 'exists' do
      expect(subject).to exist
    end
  end

  # Validate that the required mapping directive is present exactly as specified
  describe 'SSSD PKI mapping setting' do
    subject { file(sssd_conf).content.to_s }

    it "includes 'ldap_user_certificate=userCertificate;binary' exactly on a line" do
      expected = /^\s*ldap_user_certificate\s*=\s*userCertificate;binary\s*$/m
      expect(subject).to match(expected), "Expected #{sssd_conf} to contain a line: ldap_user_certificate=userCertificate;binary"
    end
  end
end
