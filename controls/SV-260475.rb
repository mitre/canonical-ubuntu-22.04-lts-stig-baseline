control 'SV-260475' do
  title 'Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.  
  
Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the NX (no-execution) bit flag is set on the system by using the following command:  
 
     $ sudo dmesg | grep -i "execute disable" 
     [    0.000000] NX (Execute Disable) protection: active  
 
If "dmesg" does not show "NX (Execute Disable) protection: active", check the hardware capabilities of the installed CPU by using the following command:   
  
     $ grep flags /proc/cpuinfo | grep -o nx | sort -u 
     nx  
  
If no output is returned, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 22.04 LTS to enable NX.  
  
If the installed CPU is hardware capable of NX protection, check if the system's BIOS/UEFI setup configuration permits toggling the "NX bit" or "no execution bit", and set it to "enabled".)
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-260475'
  tag rid: 'SV-260475r953238_rule'
  tag stig_id: 'UBTU-22-213025'
  tag fix_id: 'F-64112r953237_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  dmesg_nx_conf = command('dmesg | grep \'[NX|DX]*protection\'').stdout

  describe 'The no-execution bit flag' do
    it 'should be set in kernel messages' do
      expect(dmesg_nx_conf).to_not eq(''), 'dmesg does not set ExecShield'
    end
    unless dmesg_nx_conf.empty?
      it 'should be active' do
        expect(dmesg_nx_conf.match(/:\s+(\S+)$/).captures.first).to eq('active'), "dmesg does not show ExecShield set to 'active'"
      end
    end
  end
end
