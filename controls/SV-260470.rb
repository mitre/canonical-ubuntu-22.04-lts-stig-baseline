control 'SV-260470' do
  title 'Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access.

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Verify Ubuntu 22.04 LTS requires a password for authentication upon booting into single-user and maintenance modes by using the following command:

     $ sudo grep -i password /boot/grub/grub.cfg

     password_pbkdf2 root grub.pbkdf2.sha512.10000.03255F190F0E2F7B4F0D1C3216012309162F022A7A636771

If the root password entry does not begin with "password_pbkdf2", this is a finding.'
  desc 'fix', %q(Configure Ubuntu 22.04 LTS to require a password for authentication upon booting into single-user and maintenance modes.

Generate an encrypted (grub) password for root by using the following command:

     $ grub-mkpasswd-pbkdf2
     Enter Password:
     Reenter Password:
     PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.03255F190F0E2F7B4F0D1C3216012309162F022A7A636771

Using the hash from the output, modify the "/etc/grub.d/40_custom" file by using the following command to add a boot password:

     $ sudo sed -i '$i set superusers=\"root\"\npassword_pbkdf2 root <hash>' /etc/grub.d/40_custom

where <hash> is the hash generated by grub-mkpasswd-pbkdf2 command.

Generate an updated "grub.conf" file with the new password by using the following command:

     $ sudo update-grub)
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64199r953221_chk'
  tag severity: 'high'
  tag gid: 'V-260470'
  tag rid: 'SV-260470r953223_rule'
  tag stig_id: 'UBTU-22-212010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-64107r953222_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  grub_conf_path = input('grub_conf_path')

  if file('/sys/firmware/efi').exist?
    impact 0.0
    describe 'System running UEFI' do
      skip 'The System is running UEFI, this control is Not Applicable.'
    end
  else
    describe parse_config_file(grub_user_file) do
      its('GRUB2_PASSWORD') { should include 'grub.pbkdf2.sha512' }
    end
  end
end
