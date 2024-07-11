control 'SV-260595' do
  title "Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  desc 'To ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems must be able to allocate audit record storage capacity.  
  
The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS allocates audit record storage capacity to store at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility.  
  
Determine which partition the audit records are being written to by using the following command:  
  
     $ sudo grep -i log_file /etc/audit/auditd.conf 
     log_file = /var/log/audit/audit.log 
  
Check the size of the partition that audit records are written to (with the example being "/var/log/audit/") by using the following command:  
  
     $ sudo df -h /var/log/audit/ 
     /dev/sda2 24G 10.4G 13.6G 43% /var/log/audit 
  
If the audit records are not written to a partition made specifically for audit records ("/var/log/audit" as a separate partition), determine the amount of space being used by other files in the partition by using the following command:  
  
     $ sudo du -sh <audit_partition> 
     1.8G /var/log/audit  
  
Note: The partition size needed to capture a week's worth of audit records is based on the activity level of the system and the total storage capacity available.  
  
If the audit record partition is not allocated for sufficient storage capacity, this is a finding.)
  desc 'fix', %q(Allocate enough storage capacity for at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility.  
  
If audit records are stored on a partition made specifically for audit records, use the "parted" program to resize the partition with sufficient space to contain one week's worth of audit records.  
  
If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient amount of space will need be to be created.  
  
Set the auditd server to point to the mount point where the audit records must be located:  
  
     $ sudo sed -i -E 's@^(log_file\s*=\s*).*@\1 <audit_partition_mountpoint>/audit.log@' /etc/audit/auditd.conf  
  
where <audit_partition_mountpoint> is the aforementioned mount point.)
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-260595'
  tag rid: 'SV-260595r953598_rule'
  tag stig_id: 'UBTU-22-653035'
  tag fix_id: 'F-64232r953597_fix'
  tag cci: ['CCI-001849', 'CCI-001851']
  tag nist: ['AU-4', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_log_dir = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe file(audit_log_dir) do
    it { should exist }
    it { should be_directory }
  end

  # Fetch partition sizes in 1K blocks for consistency
  partition_info = command("df -B 1K #{audit_log_dir}").stdout.split("\n")
  partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split(' ')

  # Get unused space percentage
  percentage_space_unused = (100 - partition_sz_arr[4].to_i)

  describe "auditd_conf's space_left threshold" do
    it 'should be under the amount of space currently available (in 1K blocks) for the audit log directory' do
      expect(auditd_conf.space_left.to_i).to be <= percentage_space_unused
    end
  end
end
