control 'SV-260587' do
  title 'Ubuntu 22.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify there is a script that offloads audit data and that script runs weekly by using the following command:

Note: If the system is not connected to a network, this requirement is not applicable.

     $ ls /etc/cron.weekly
     <audit_offload_script_name>

Check if the script inside the file does offloading of audit logs to external media.

If the script file does not exist or does not offload audit logs, this is a finding.'
  desc 'fix', 'Create a script that offloads audit logs to external media and runs weekly.

The script must be located in the "/etc/cron.weekly" directory.'
  impact 0.3
  tag check_id: 'C-64316r953572_chk'
  tag severity: 'low'
  tag gid: 'V-260587'
  tag rid: 'SV-260587r959008_rule'
  tag stig_id: 'UBTU-22-651035'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-64224r953573_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers or airgapped systems', impact: 0.0) {
    !(%w[docker podman kubepods lxc lxd].include?(virtualization.system) && virtualization.role == 'guest') && !input('airgapped_system')
  }

  cron_file = input('auditoffload_config_file')

  describe file(cron_file) do
    it { should exist }
    it { should be_file }
    it { should be_executable }
    its('content') { should_not be_empty }
  end

  describe 'cron script path' do
    subject { cron_file }
    it { should start_with('/etc/cron.weekly/') }
  end

  describe 'Manual review - validate audit offload behavior' do
    skip "Manual verification required: Confirm that the weekly script at #{cron_file} offloads audit events to external media."
  end
end
