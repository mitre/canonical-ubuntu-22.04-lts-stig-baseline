control 'SV-260562' do
  title 'Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces password complexity by requiring that at least one numeric character be used by using the following command:

     $ grep -i dcredit /etc/security/pwquality.conf
     dcredit = -1

If "dcredit" is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce password complexity by requiring that at least one numeric character be used.

Add or modify the following line in the "/etc/security/pwquality.conf" file:

dcredit = -1'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag gid: 'V-260562'
  tag rid: 'SV-260562r953997_rule'
  tag stig_id: 'UBTU-22-611020'
  tag fix_id: 'F-64199r953498_fix'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'dcredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `dcredit` set' do
      expect(value).not_to be_empty, 'dcredit is not set in pwquality.conf'
    end

    it 'only sets `dcredit` once' do
      expect(value.length).to eq(1), 'dcredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `dcredit` to a positive value' do
      expect(value.first.to_i).to be < 0, 'dcredit is not set to a negative value in pwquality.conf'
    end
  end
end
