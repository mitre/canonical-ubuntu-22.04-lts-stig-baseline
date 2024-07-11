control 'SV-260473' do
  title 'Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.'
  desc 'check', 'Verify that kernel core dumps are disabled unless needed by using the following command:  
  
     $ systemctl status kdump.service 
     kdump.service 
          Loaded: masked (Reason: Unit kdump.service is masked.) 
          Active: inactive (dead) 
  
If "kdump.service" is not masked and inactive, ask the system administrator (SA) if the use of the service is required and documented with the information system security officer (ISSO).  
  
If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If kernel core dumps are not required, disable and mask "kdump.service" by using the following command:  
 
     $ sudo systemctl mask kdump --now 
  
If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64202r953230_chk'
  tag severity: 'medium'
  tag gid: 'V-260473'
  tag rid: 'SV-260473r953232_rule'
  tag stig_id: 'UBTU-22-213015'
  tag gtitle: 'SRG-OS-000184-GPOS-00078'
  tag fix_id: 'F-64110r953231_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001190']
  tag nist: ['CM-6 b', 'SC-24']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('kdump') do
    it { should_not be_running }
    its('params.LoadState') { should cmp 'masked' }
    its('params.UnitFileState') { should cmp 'masked' }
  end
end
