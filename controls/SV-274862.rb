control 'SV-274862' do
  title 'Ubuntu 22.04 LTS must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user, must have the permissions 755 or more restrictive, and should have no extended rights that allow any nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to audit the execution of any system call made by cron as root or as any privileged user.

 $ sudo auditctl -l | grep /etc/cron.d
 -w /etc/cron.d -p wa -k cronjobs

 $ sudo auditctl -l | grep /var/spool/cron
 -w /var/spool/cron -p wa -k cronjobs

 If either of these commands do not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of any system call made by cron as root or as any privileged user.

 Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
 -w /etc/cron.d/ -p wa -k cronjobs
 -w /var/spool/cron/ -p wa -k cronjobs

 To load the rules to the kernel immediately, use the following command:

 $ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78963r1155187_chk'
  tag severity: 'medium'
  tag gid: 'V-274862'
  tag rid: 'SV-274862r1155211_rule'
  tag stig_id: 'UBTU-22-654041'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78868r1155188_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # Validate audit rules for cron directories using native auditd resource and inputs-resolved keynames
  audited_paths = %w[/etc/cron.d /var/spool/cron]
  expected_keys = (input('audit_rule_keynames') || {}).merge(input('audit_rule_keynames_overrides') || {})

  audited_paths.each do |audit_path|
    describe "Audit rules for #{audit_path}" do
      it "#{audit_path} is audited properly" do
        audit_rule = auditd.file(audit_path)
        expect(audit_rule).to exist
        expect(audit_rule.permissions.flatten).to include('w', 'a')
        expect(audit_rule.key.uniq).to include(expected_keys[audit_path])
      end
    end
  end
end
