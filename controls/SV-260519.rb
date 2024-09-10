control 'SV-260519' do
  title 'Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

Note that USNO offers authenticated NTP service to DOD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/DOD-customers for more information.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to compare the system clock at least every 24 hours to the authoritative time source by using the following command:

Note: If the system is not networked, this requirement is not applicable.

     $ sudo grep maxpoll -ir /etc/chrony*
     server tick.usno.navy.mil iburst maxpoll 16

If the "maxpoll" option is set to a number greater than 16, the line is commented out, or is missing, this is a finding.

Verify that the "chrony.conf" file is configured to an authoritative DOD time source by using the following command:

     $ sudo grep -ir server /etc/chrony*
     server tick.usno.navy.mil iburst maxpoll 16
     server tock.usno.navy.mil iburst maxpoll 16
     server ntp2.usno.navy.mil iburst maxpoll 16

If "server" is not defined, is not set to an authoritative DOD time source, is commented out, or missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to compare the system clock at least every 24 hours to the authoritative time source.

Add or modify the following line in the "/etc/chrony/chrony.conf" file:

server [source] iburst maxpoll = 16

Restart "chrony.service" for the changes to take effect by using the following command:

     $ sudo systemctl restart chrony.service'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000359-GPOS-00146']
  tag gid: 'V-260519'
  tag rid: 'SV-260519r954017_rule'
  tag stig_id: 'UBTU-22-252010'
  tag fix_id: 'F-64156r953369_fix'
  tag cci: ['CCI-001891', 'CCI-001890', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 b', 'AU-8 (1) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  time_sources = ntp_conf('/etc/chrony.conf').server

  # Cover case when a single server is defined and resource returns a string and not an array
  time_sources = [time_sources] if time_sources.is_a? String

  unless time_sources.nil?
    max_poll_values = time_sources.map { |val|
      val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
    }
  end

  # Verify the "chrony.conf" file is configured to an authoritative DoD time source by running the following command:

  describe ntp_conf('/etc/chrony.conf') do
    its('server') { should_not be_nil }
  end

  unless ntp_conf('/etc/chrony.conf').server.nil?
    if ntp_conf('/etc/chrony.conf').server.is_a? String
      describe ntp_conf('/etc/chrony.conf') do
        its('server') { should match input('authoritative_timeserver') }
      end
    end

    if ntp_conf('/etc/chrony.conf').server.is_a? Array
      describe ntp_conf('/etc/chrony.conf') do
        its('server.join') { should match input('authoritative_timeserver') }
      end
    end
  end
  # All time sources must contain valid maxpoll entries
  unless time_sources.nil?
    describe 'chronyd maxpoll values (99=maxpoll absent)' do
      subject { max_poll_values }
      it { should all be < 17 }
    end
  end
end
