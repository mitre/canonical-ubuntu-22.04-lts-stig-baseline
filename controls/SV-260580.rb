control 'SV-260580' do
  title 'Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted certificate authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.  
  
The DOD will only accept PKI-certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.'
  desc 'check', 'Verify the directory containing the root certificates for Ubuntu 22.04 LTS contains certificate files for DOD PKI-established certificate authorities by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA". 
 
     $ ls /etc/ssl/certs | grep -i DOD 
     DOD_PKE_CA_chain.pem 
 
If no DOD root certificate is found, this is a finding. 
 
Verify that all root certificates present on the system have been approved by the AO. 
 
     $ ls /etc/ssl/certs 
 
If a certificate is present that is not approved by the AO, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to use of DOD PKI-established certificate authorities for verification of the establishment of protected sessions.  
 
Add at least one DOD certificate authority to the "/usr/share/ca-certificates" directory in the CRT format.  
  
Update the "/etc/ssl/certs" directory by using the following command:  
  
     $ sudo dpkg-reconfigure ca-certificates'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64309r953551_chk'
  tag severity: 'medium'
  tag gid: 'V-260580'
  tag rid: 'SV-260580r953553_rule'
  tag stig_id: 'UBTU-22-631010'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-64217r953552_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
