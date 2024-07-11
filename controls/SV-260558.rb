control 'SV-260558' do
  title 'Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.   
  
When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" by using the following command:  
  
     $ sudo grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* 
  
If any occurrences of "NOPASSWD" or "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "NOPASSWD" or "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-260558'
  tag rid: 'SV-260558r954043_rule'
  tag stig_id: 'UBTU-22-432010'
  tag fix_id: 'F-64195r953486_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  describe sudoers(input('sudoers_config_files')) do
    its('settings.Defaults') { should_not include '!authenticate' }
  end
end
