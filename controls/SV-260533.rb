control 'SV-260533' do
  title 'Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest algorithm available to secure the SSH connection.'
  desc 'check', %q(Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms'
     /etc/ssh/sshd_config:KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

If "KexAlgorithms" does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

Restart the SSH server for changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-64262r953410_chk'
  tag severity: 'medium'
  tag gid: 'V-260533'
  tag rid: 'SV-260533r958408_rule'
  tag stig_id: 'UBTU-22-255060'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-64170r953411_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  openssh_present = package('openssh-server').installed?

  # Not applicable in containers when OpenSSH server is not installed
  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !((%w[docker podman kubepods lxc lxd].include?(virtualization.system) && virtualization.role == 'guest') && !openssh_present)
  }

  expected_kex = %w[
    ecdh-sha2-nistp256
    ecdh-sha2-nistp384
    ecdh-sha2-nistp521
    diffie-hellman-group-exchange-sha256
  ]

  # Use `sshd -T` to evaluate the effective configuration as loaded by sshd
  sshd_t_output = command('/usr/sbin/sshd -T 2>/dev/null').stdout
  kex_line = sshd_t_output.lines.find { |l| l.start_with?('kexalgorithms ') }
  actual_kex = kex_line.nil? ? [] : kex_line.split(/\s+/, 2)[1].to_s.strip.split(',')

  describe 'Effective SSHD KexAlgorithms' do
    subject { actual_kex }
    it 'is set and exactly matches the required FIPS-validated algorithms in order' do
      expect(subject).to eq(expected_kex), <<~MSG.chomp
        Expected KexAlgorithms to be exactly (in order):
          - #{expected_kex.join("\n  - ")}
        Actual:
          - #{actual_kex.join("\n  - ")}
      MSG
    end
  end
end
