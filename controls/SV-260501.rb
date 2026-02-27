control 'SV-260501' do
  title 'Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal directories are owned by "root" by using the following command:

     $ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \\;
     /run/log/journal root
     /var/log/journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce root

If any output returned is not owned by "root", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to set the appropriate ownership to the directories used by the systemd journal:

Add or modify the following lines in the "/usr/lib/tmpfiles.d/systemd.conf" file:

z /run/log/journal 2640 root systemd-journal - -
z /var/log/journal 2640 root systemd-journal - -

Restart the system for the changes to take effect.'
  impact 0.5
  tag check_id: 'C-64230r953314_chk'
  tag severity: 'medium'
  tag gid: 'V-260501'
  tag rid: 'SV-260501r958566_rule'
  tag stig_id: 'UBTU-22-232080'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64138r953315_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  journal_bases = %w[/run/log/journal /var/log/journal]

  journal_bases.each do |base|
    if file(base).exist?
      describe "Systemd journal directory ownership under #{base}" do
        subject do
          command("find -L #{base} -type d ! -user root -print 2>/dev/null").stdout.split("\n").reject(&:empty?)
        end

        it 'should have all directories owned by root' do
          expect(subject).to be_empty, "Directories under #{base} not owned by root:\n\t- #{subject.join("\n\t- ")}"
        end
      end
    else
      describe "Systemd journal directory #{base}" do
        skip "#{base} does not exist; skipping ownership validation per applicability"
      end
    end
  end
end
