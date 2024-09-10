control 'SV-260507' do
  title 'Ubuntu 22.04 LTS must configure audit tools to be owned by "root".'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify Ubuntu 22.04 LTS configures the audit tools to be owned by "root" to prevent any unauthorized access with the following command:

     $ stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
     /sbin/auditctl root
     /sbin/aureport root
     /sbin/ausearch root
     /sbin/autrace root
     /sbin/auditd root
     /sbin/audispd-zos-remote root
     /sbin/augenrules root

If any of the audit tools are not owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit tools on Ubuntu 22.04 LTS to be protected from unauthorized access by setting the file owner as root using the following command:

     $ sudo chown root <audit_tool_name>

Replace "<audit_tool_name>" with each audit tool not owned by "root".'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag gid: 'V-260507'
  tag rid: 'SV-260507r953334_rule'
  tag stig_id: 'UBTU-22-232110'
  tag fix_id: 'F-64144r953333_fix'
  tag cci: ['CCI-001493', 'CCI-001494']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_tools = ['/sbin/auditctl', '/sbin/aureport', '/sbin/ausearch', '/sbin/autrace', '/sbin/auditd', '/sbin/rsyslogd', '/sbin/augenrules']

  failing_tools = audit_tools.reject { |at| file(at).owned_by?('root') }

  describe 'Audit executables' do
    it 'should be owned by root' do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
