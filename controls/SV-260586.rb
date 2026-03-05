control 'SV-260586' do
  title 'Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools by using the following command:

     $ grep -E '(\\/sbin\\/(audit|au))' /etc/aide/aide.conf
     /sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
     /sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
     /sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
     /sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
     /sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
     /sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

If any of the lines do not appear as shown, are commented out, or are missing, this is a finding."
  desc 'fix', 'Configure AIDE to protect the integrity of audit tools:

Add or modify the following lines in the "/etc/aide/aide.conf" file:

# Audit Tools
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag gid: 'V-260586'
  tag rid: 'SV-260586r1069107_rule'
  tag stig_id: 'UBTU-22-651030'
  tag fix_id: 'F-64223r1044778_fix'
  tag cci: ['CCI-001496', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 (3)', 'AU-9 a', 'AU-9']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(%w[docker podman kubepods lxc lxd].include?(virtualization.system) && virtualization.role == 'guest')
  }

  audit_tools = %w[/sbin/auditctl
                   /sbin/auditd
                   /sbin/ausearch
                   /sbin/aureport
                   /sbin/autrace
                   /sbin/augenrules]

  audit_rule_suffix = 'p+i+n+u+g+s+b+acl+xattrs+sha512'

  if package('aide').installed?
    describe file('/etc/aide/aide.conf') do
      it { should exist }
    end

    describe 'AIDE audit tools selection lines' do
      subject do
        content = file('/etc/aide/aide.conf').content.to_s
        audit_tools.reject do |tool|
          content.lines.any? { |line| line.match?(/^#{Regexp.escape(tool)}\s+#{Regexp.escape(audit_rule_suffix)}$/) }
        end
      end
      it 'must include exact lines for all audit tools' do
        expect(subject).to be_empty, "Missing or incorrect lines in /etc/aide/aide.conf for: #{subject.join(', ')}"
      end
    end
  else
    describe 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE)' do
      skip 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE), manual review is required.'
    end
  end
end
