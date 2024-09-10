control 'SV-260546' do
  title 'Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces a 60-day maximum password lifetime for new user accounts by using the following command:

     $ grep -i pass_max_days /etc/login.defs
     PASS_MAX_DAYS    60

If "PASS_MAX_DAYS" is less than "60", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce a 60-day maximum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS    60'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-260546'
  tag rid: 'SV-260546r954038_rule'
  tag stig_id: 'UBTU-22-411030'
  tag fix_id: 'F-64183r953450_fix'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')
  setting = input_object('pass_max_days').name.upcase

  describe "/etc/login.defs does not have `#{setting}` configured" do
    let(:config) { login_defs.read_params[setting] }
    it "greater than #{value} day" do
      expect(config).to cmp <= value
    end
  end
end
