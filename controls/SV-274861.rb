control 'SV-274861' do
  title 'The operating system must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', "Verify the operating system restricts privilege elevation to authorized personnel with the following command:

$ sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL"
  desc 'fix', 'Configure the operating system to restrict privilege elevation to authorized personnel.

Remove the following entries from the /etc/sudoers file or any configuration file under /etc/sudoers.d/:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  tag check_id: 'C-78962r1101702_chk'
  tag severity: 'medium'
  tag gid: 'V-274861'
  tag rid: 'SV-274861r1101704_rule'
  tag stig_id: 'UBTU-22-654224'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78867r1101703_fix'
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  sudo = sudoers(input('sudoers_config_files'))

  disallowed = sudo.rules.where {
    users == 'ALL' &&
      hosts == 'ALL' &&
      !run_as.nil? && ['ALL', 'ALL:ALL'].include?(run_as) &&
      commands == 'ALL'
  }.entries

  disallowed_details = disallowed.map { |r| "#{r[:users]} #{r[:hosts]}=(#{r[:run_as]}) #{r[:commands]}" }.join('; ')

  describe 'Disallowed ALL-to-ALL sudoers entries' do
    subject { disallowed }
    it 'should be empty (no lines allowing ALL users to execute ALL commands as ALL)' do
      expect(subject).to be_empty, "Found disallowed sudoers entries: #{disallowed_details}"
    end
  end
end
