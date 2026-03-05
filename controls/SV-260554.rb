control 'SV-260554' do
  title 'Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to automatically exit interactive command shell user sessions after 15 minutes of inactivity or less by using the following command:

     $ sudo grep -E "\\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*
     /etc/profile.d/99-terminal_tmout.sh:TMOUT=900

If "TMOUT" is not set to "900" or less, is set to "0", is commented out, or missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to exit interactive command shell user sessions after 15 minutes of inactivity.

Create and/or append a custom file under "/etc/profile.d/" by using the following command:

     $ sudo su -c "echo TMOUT=900 >> /etc/profile.d/99-terminal_tmout.sh"

This will set a timeout value of 15 minutes for all future sessions.

To set the timeout for the current sessions, execute the following command over the terminal session:

     $ export TMOUT=900'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-260554'
  tag rid: 'SV-260554r958636_rule'
  tag stig_id: 'UBTU-22-412030'
  tag fix_id: 'F-64191r953474_fix'
  tag cci: ['CCI-000057', 'CCI-000060', 'CCI-002361']
  tag nist: ['AC-11 a', 'AC-11 (1)', 'AC-12']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(%w[docker podman kubepods lxc lxd].include?(virtualization.system) && virtualization.role == 'guest')
  }

  timeout_setting = command("grep -E '\\bTMOUT=[0-9]+' /etc/bash.bashrc /etc/profile.d/*.sh 2>/dev/null | tail -n1").stdout.strip.match(/TMOUT=(?<timeout>\d+)/)
  expected_timeout = input('system_activity_timeout')

  describe 'Shell inactivity timeout (TMOUT)' do
    it 'should be set' do
      expect(timeout_setting).to_not be_nil, 'TMOUT not set in /etc/bash.bashrc or /etc/profile.d/*.sh'
    end
    unless timeout_setting.nil?
      it "should lock the session after #{expected_timeout} seconds" do
        expect(timeout_setting['timeout'].to_i).to cmp <= expected_timeout
      end
    end
  end
end
