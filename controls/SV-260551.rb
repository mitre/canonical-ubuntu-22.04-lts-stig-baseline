control 'SV-260551' do
  title 'Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last occurred by using the following command:  
  
     $ grep pam_lastlog /etc/pam.d/login 
     session     required     pam_lastlog.so     showfailed 
  
If the line containing "pam_lastlog" is not set to "required", or the "silent" option is present, the "showfailed" option is missing, the line is commented out, or the line is missing , this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to provide users with feedback on when account accesses last occurred. 
  
Add or modify the following line at the top in the "/etc/pam.d/login" file:  
  
session     required     pam_lastlog.so     showfailed'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-260551'
  tag rid: 'SV-260551r953466_rule'
  tag stig_id: 'UBTU-22-412015'
  tag fix_id: 'F-64188r953465_fix'
  tag cci: ['CCI-000366', 'CCI-000052']
  tag nist: ['CM-6 b', 'AC-9']
  tag 'host'
  tag 'container'

  describe pam('/etc/pam.d/postlogin') do
    its('lines') { should match_pam_rule('session .* pam_lastlog.so').all_with_args('showfailed') }
    its('lines') { should_not match_pam_rule('session .* pam_lastlog.so').all_without_args('silent') }
  end
end
