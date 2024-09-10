control 'SV-260603' do
  title 'Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', %q(Verify that "/etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files are owned by root group by using the following command:

     $ sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $4, $9}'
     root /etc/audit/audit.rules
     root /etc/audit/auditd.conf
     root /etc/audit/rules.d/audit.rules

If "/etc/audit/audit.rules", "/etc/audit/auditd.conf", or "/etc/audit/rules.d/*" files are owned by a group other than "root", this is a finding.)
  desc 'fix', 'Configure "/etc/audit/audit.rules", "/etc/audit/rules.d/*", and "/etc/audit/auditd.conf" files to be owned by root group by using the following command:

     $ sudo chown -R :root /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/*'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64332r953620_chk'
  tag severity: 'medium'
  tag gid: 'V-260603'
  tag rid: 'SV-260603r953622_rule'
  tag stig_id: 'UBTU-22-653075'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-64240r953621_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    log_file = auditd_conf.log_file
    admin_groups = input('admin_groups')

    log_file_exists = !log_file.nil?
    if log_file_exists
      describe file(log_file) do
        its('group') { should be_in admin_groups }
      end
    else
      describe('Audit log file ' + log_file + ' exists') do
        subject { log_file_exists }
        it { should be true }
      end
    end
  end
end
