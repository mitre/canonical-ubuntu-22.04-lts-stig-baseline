control 'SV-260577' do
  title 'Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.  
  
A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.  
  
When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a certification authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.  
  
This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor.  
  
Determine which pkcs11 module is being used via the "use_pkcs11_module" in "/etc/pam_pkcs11/pam_pkcs11.conf" and then ensure "ca" is enabled in "cert_policy" by using the following command:  
   
     $ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca   
     cert_policy = ca,signature,ocsp_on;  
  
If "cert_policy" is not set to "ca", the line is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS, for PKI-based authentication, to validate certificates by constructing a certification path to an accepted trust anchor.  
  
Add or modify all "cert_policy" lines in the "/etc/pam_pkcs11/pam_pkcs11.conf" file with the following: 
 
cert_policy = ca,signature,ocsp_on;  
  
Note: If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000384-GPOS-00167']
  tag gid: 'V-260577'
  tag rid: 'SV-260577r953544_rule'
  tag stig_id: 'UBTU-22-612030'
  tag fix_id: 'F-64214r953543_fix'
  tag cci: ['CCI-000185', 'CCI-001991']
  tag nist: ['IA-5 (2) (a)', 'IA-5 (2) (b) (1)', 'IA-5 (2) (d)']
  tag 'host'
  tag 'container'

  only_if('If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.', impact: 0.0) {
    !input('smart_card_enabled')
  }

  root_ca_file = input('root_ca_file')
  describe file(root_ca_file) do
    it { should exist }
  end

  describe 'Ensure the RootCA is a DoD-issued certificate with a valid date' do
    if file(root_ca_file).exist?
      subject { x509_certificate(root_ca_file) }
      it 'has the correct issuer_dn' do
        expect(subject.issuer_dn).to match('/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 3')
      end
      it 'has the correct subject_dn' do
        expect(subject.subject_dn).to match('/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 3')
      end
      it 'is valid' do
        expect(subject.validity_in_days).to be > 0
      end
    end
  end
end
