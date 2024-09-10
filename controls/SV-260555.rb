control 'SV-260555' do
  title 'Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.'
  desc 'Setting the most restrictive default permissions ensures newly created accounts do not have unnecessary access.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS defines default permissions for all authenticated users in such a way that the user can read and modify only their own files by using the following command:

     $ grep -i '^\s*umask' /etc/login.defs
     UMASK 077

If the "UMASK" variable is set to "000", this is a finding with the severity raised to a CAT I.

If "UMASK" is not set to "077", is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to define the default permissions for all authenticated users in such a way that the user can read and modify only their own files.

Add or modify the following line in the "/etc/login.defs" file:

UMASK 077'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag gid: 'V-260555'
  tag rid: 'SV-260555r953478_rule'
  tag stig_id: 'UBTU-22-412035'
  tag fix_id: 'F-64192r953477_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  permissions_for_shells = input('permissions_for_shells')

  describe login_defs do
    its('UMASK') { should cmp permissions_for_shells['default_umask'] }
  end
end
