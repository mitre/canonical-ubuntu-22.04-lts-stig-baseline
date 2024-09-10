control 'SV-260472' do
  title 'Ubuntu 22.04 LTS must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to restrict access to the kernel message buffer by using the following command:

     $ sysctl kernel.dmesg_restrict
     kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Verify that there are no configurations that enable the kernel dmesg function:

     $ sudo grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     /etc/sysctl.d/10-kernel-hardening.conf:kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1", is commented out, is missing, or conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to restrict access to the kernel message buffer.

Add or modify the following line in the "/etc/sysctl.conf" file:

kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations:

/run/sysctl.d/
/etc/sysctl.d/
/usr/local/lib/sysctl.d/
/usr/lib/sysctl.d/
/lib/sysctl.d/
/etc/sysctl.conf

Reload settings from all system configuration files by using the following command:

     $ sudo sysctl --system'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-260472'
  tag rid: 'SV-260472r953229_rule'
  tag stig_id: 'UBTU-22-213010'
  tag fix_id: 'F-64109r953228_fix'
  tag cci: ['CCI-001090', 'CCI-001082']
  tag nist: ['SC-4', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.dmesg_restrict'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  describe kernel_parameter(parameter) do
    its('value') { should eq value }
  end

  search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

  correct_result = search_results.any? { |line| line.match(regexp) }
  incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

  describe 'Kernel config files' do
    it "should configure '#{parameter}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
