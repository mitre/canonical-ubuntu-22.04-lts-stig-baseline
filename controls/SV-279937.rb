control 'SV-279937' do
  title 'Ubuntu 22.04 LTS must not have the nfs-kernel-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', "Verify that Ubuntu does not have nfs packages installed.

Check if packages are installed:
$ sudo dpkg -l | grep -E 'nfs-common | nfs-kernel-server'

If the nfs-common or nfs-kernel-server packages are installed, this is a finding."
  desc 'fix', 'Configure the Ubuntu operating system to disable nonessential capabilities by removing the nfs-common and nfs-kernel-server packages from the system with the following commands:

Remove packages if present:
$ sudo apt purge --yes nfs-common nfs-kernel-server

Remove any unneeded dependencies:
$ sudo apt autoremove --yes

Verify that NFS services are gone:
$ sudo systemctl list-units --type=service | grep nfs'
  impact 0.7
  tag check_id: 'C-84497r1156362_chk'
  tag severity: 'high'
  tag gid: 'V-279937'
  tag rid: 'SV-279937r1156364_rule'
  tag stig_id: 'UBTU-22-215040'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-84402r1156363_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(%w[docker podman kubepods lxc lxd].include?(virtualization.system) && virtualization.role == 'guest')
  }

  nfs_packages = %w[nfs-common nfs-kernel-server]
  installed = nfs_packages.select { |pkg| package(pkg).installed? }

  describe 'NFS packages' do
    subject { installed }
    it 'should not be installed (nfs-common and nfs-kernel-server)' do
      expect(subject).to be_empty, "Installed NFS packages found: #{subject.join(', ')}"
    end
  end
end
