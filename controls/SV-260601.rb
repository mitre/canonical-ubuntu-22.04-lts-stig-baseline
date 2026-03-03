control 'SV-260601' do
  title 'Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', %q(Verify that "/etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files have a mode of "640" or less permissive by using the following command:

     $ sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $1, $9}'
     -rw-r----- /etc/audit/audit.rules
     -rw-r----- /etc/audit/auditd.conf
     -rw-r----- /etc/audit/rules.d/audit.rules

If "/etc/audit/audit.rules", "/etc/audit/auditd.conf", or "/etc/audit/rules.d/*" files have a mode more permissive than "640", this is a finding.)
  desc 'fix', 'Configure /etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files to have a mode of "640" by using the following command:

     $ sudo chmod -R 640 /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag gid: 'V-260601'
  tag rid: 'SV-260601r958444_rule'
  tag stig_id: 'UBTU-22-653065'
  tag fix_id: 'F-64238r953615_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  expected_mode = input('audit_conf_mode')
  rules_dir_files = command("find /etc/audit/rules.d -maxdepth 1 -type f -printf '%p\\n' 2>/dev/null").stdout.split("\n").reject(&:empty?)
  audit_files = ['/etc/audit/auditd.conf', '/etc/audit/audit.rules'] + rules_dir_files
  existing_files = audit_files.select { |p| file(p).exist? }
  failing_files = existing_files.select { |p| file(p).more_permissive_than?(expected_mode) }

  describe 'Audit configuration files' do
    subject { failing_files }
    it "should be no more permissive than '#{expected_mode}'" do
      expect(subject).to be_empty, "Failing files:\n\t- #{subject.join("\n\t- ")}"
    end
  end
end
