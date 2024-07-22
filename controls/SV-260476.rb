control 'SV-260476' do
  title 'Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.  
  
Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.  
  
Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DOD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify that APT is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization by using the following command:  
  
     $ grep -i allowunauthenticated /etc/apt/apt.conf.d/* 
     /etc/apt/apt.conf.d/01-vendor-ubuntu:APT::Get::AllowUnauthenticated "false"; 
  
If "APT::Get::AllowUnauthenticated" is not set to "false", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure APT to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.  
  
Add or modify the following line in any file under the "/etc/apt/apt.conf.d/" directory: 
 
APT::Get::AllowUnauthenticated "false";'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64205r953239_chk'
  tag severity: 'low'
  tag gid: 'V-260476'
  tag rid: 'SV-260476r954022_rule'
  tag stig_id: 'UBTU-22-214010'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-64113r953240_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe directory('/etc/apt/apt.conf.d') do
    it { should exist }
  end

  apt_allowunauth = command('grep -i allowunauth /etc/apt/apt.conf.d/*').stdout.strip.split("\n")
  if apt_allowunauth.empty?
    describe 'apt conf files do not contain AllowUnauthenticated' do
      subject { apt_allowunauth.empty? }
      it { should be true }
    end
  else
    apt_allowunauth.each do |line|
      describe "#{line} contains AllowUnauthenctication" do
        subject { line }
        it { should_not match(/.*false.*/) }
      end
    end
  end
end
