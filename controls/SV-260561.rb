control 'SV-260561' do
  title 'Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  
  
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces password complexity by requiring that at least one lowercase character be used by using the following command:  
  
     $ grep -i lcredit /etc/security/pwquality.conf 
     lcredit = -1  
  
If "lcredit" is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce password complexity by requiring that at least one lowercase character be used.  
 
Add or modify the following line in the "/etc/security/pwquality.conf" file: 
 
lcredit = -1'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag gid: 'V-260561'
  tag rid: 'SV-260561r953996_rule'
  tag stig_id: 'UBTU-22-611015'
  tag fix_id: 'F-64198r953495_fix'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'lcredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `lcredit` set' do
      expect(value).not_to be_empty, 'lcredit is not set in pwquality.conf'
    end

    it 'only sets `lcredit` once' do
      expect(value.length).to eq(1), 'lcredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `lcredit` to a positive value' do
      expect(value.first.to_i).to be < 0, 'lcredit is not set to a negative value in pwquality.conf'
    end
  end
end
