control 'SV-260517' do
  title 'Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces.'
  desc 'Denial of service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify an application firewall is configured to rate limit any connection to the system.

Check all the services listening to the ports by using the following command:

     $ ss -l46ut
     Netid               State          Recv-Q          Send-Q                               Local Address:Port            Peer Address:Port               Process
     tcp                 LISTEN               0                     511                                           *:http                                          *:*
     tcp                 LISTEN               0                     128                                           [::]:ssh                                        [::]:*
     tcp                 LISTEN               0                     128                                           [::]:ipp                                        [::]:*
     tcp                 LISTEN               0                     128                                           [::]:smtp                                    [::]:*


For each entry, verify that the ufw is configured to rate limit the service ports by using the following command:

     $ sudo ufw status
     Status: active

     To                           Action     From
     --                             ------         ----
     80/tcp                    LIMIT       Anywhere
     25/tcp                    LIMIT       Anywhere
     Anywhere            DENY       240.9.19.81
     443                           LIMIT      Anywhere
     22/tcp                     LIMIT      Anywhere
     80/tcp (v6)            LIMIT      Anywhere
     25/tcp (v6)            LIMIT      Anywhere
     22/tcp (v6)            LIMIT      Anywhere (v6)

     25                             DENY OUT    Anywhere
     25 (v6)                    DENY OUT    Anywhere (v6)

If any port with a state of "LISTEN" that does not have an action of "DENY", is not marked with the "LIMIT" action, this is a finding.'
  desc 'fix', 'Configure the application firewall to protect against or limit the effects of DoS attacks by ensuring Ubuntu 22.04 LTS is implementing rate-limiting measures on impacted network interfaces.

For each service with a port listening to connections, run the following command, replacing "<service_name>" with the service that needs to be rate limited.

     $ sudo ufw limit <service_name>

Rate-limiting can also be done on an interface. An example of adding a rate limit on the "ens160" interface follows:

     $ sudo ufw limit in on ens160'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-260517'
  tag rid: 'SV-260517r958902_rule'
  tag stig_id: 'UBTU-22-251025'
  tag fix_id: 'F-64154r953363_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5', 'SC-5 a']
  tag 'host'

  # Not applicable to containers
  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # Collect listening TCP/UDP ports in the form "<port>/<proto>" (e.g., "22/tcp", "53/udp")
  ss_output = command('ss -l46utnH').stdout
  listening = ss_output.to_s.each_line.filter_map do |line|
    fields = line.split
    next nil unless fields && fields.length >= 5

    proto = fields[0].to_s.downcase # tcp or udp
    local = fields[4].to_s
    # Local is like 0.0.0.0:22 or [::]:53; take last ':' segment as port
    port = local.split(':').last
    next nil unless %w[tcp udp].include?(proto) && port =~ /^\d+$/

    "#{port}/#{proto}"
  end.uniq.sort

  # Parse UFW status for actions per "<port>/<proto>"
  ufw_status = command('ufw status').stdout
  rules_map = Hash.new { |h, k| h[k] = [] }
  ufw_status.to_s.each_line do |raw|
    line = raw.strip
    next if line.empty?

    # Match rows like: "80/tcp       LIMIT   Anywhere" or "22/tcp (v6)  LIMIT  Anywhere"
    m = line.match(/^(?<to>.+?)\s{2,}(?<action>ALLOW|DENY|LIMIT)(?:\s{2,}.+)?$/)
    next unless m

    to = m[:to].strip.gsub(/\s+\(v6\)\z/, '')
    action = m[:action]
    # Normalize to "<port>/<proto>"
    if to =~ %r{^(\d+)/(tcp|udp)\b}
      key = "#{Regexp.last_match(1)}/#{Regexp.last_match(2)}"
      rules_map[key] |= [action]
    end
  end

  non_compliant = listening.reject do |pp|
    actions = rules_map[pp]
    actions.include?('DENY') || actions.include?('LIMIT')
  end

  describe 'Listening service ports must be rate limited (or denied) by ufw' do
    subject { non_compliant }
    it 'should be empty' do
      expect(subject).to be_empty, <<~MSG
        The following listening ports lack a corresponding ufw LIMIT or DENY rule:
          - #{subject.join("\n  - ")}
        Remediation: run `ufw limit <service|port>` for each listed port (or explicitly `ufw deny` if the service must be blocked).
      MSG
    end
  end
end
