control 'SV-260552' do
  title 'Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Ubuntu 22.04 LTS management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service (DoS) attacks.  
  
This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS limits the number of concurrent sessions to 10 for all accounts and/or account types by using the following command:  
  
     $ sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf 
     /etc/security/limits.conf:* hard maxlogins 10 
 
If "maxlogins" does not have a value of "10" or less, is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to limit the number of concurrent sessions to 10 for all accounts and/or account types.  
  
Add or modify the following line at the top of the "/etc/security/limits.conf" file:  
  
* hard maxlogins 10'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-260552'
  tag rid: 'SV-260552r953469_rule'
  tag stig_id: 'UBTU-22-412020'
  tag fix_id: 'F-64189r953468_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  setting = 'maxlogins'
  expected_value = input('concurrent_sessions_permitted')

  limits_files = command('ls /etc/security/limits.d/*.conf').stdout.strip.split
  limits_files.append('/etc/security/limits.conf')

  # make sure that at least one limits.conf file has the correct setting
  globally_set = limits_files.any? { |lf| !limits_conf(lf).read_params['*'].nil? && limits_conf(lf).read_params['*'].include?(['hard', setting.to_s, expected_value.to_s]) }

  # make sure that no limits.conf file has a value that contradicts the global set
  failing_files = limits_files.select { |lf|
    limits_conf(lf).read_params.values.flatten(1).any? { |l|
      l[1].eql?(setting) && l[2].to_i > expected_value
    }
  }
  describe 'Limits files' do
    it "should limit concurrent sessions to #{expected_value} by default" do
      expect(globally_set).to eq(true), "No global ('*') setting for concurrent sessions found"
    end
    it 'should not have any conflicting settings' do
      expect(failing_files).to be_empty, "Files with incorrect '#{setting}' settings:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
