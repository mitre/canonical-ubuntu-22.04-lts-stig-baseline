control 'SV-260484' do
  title 'Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest.'
  desc 'Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Verify Ubuntu 22.04 LTS prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.

Note: If there is a documented and approved reason for not having data-at-rest encryption, this requirement is not applicable.

Determine the partition layout for the system by using the following command:

     $ sudo fdisk -l

     ...
     Device               Start               End        Sectors       Size  Type
     /dev/sda1         2048      2203647       2201600          1G  EFI System
     /dev/sda2  2203648      6397951       4194304          2G  Linux filesystem
     /dev/sda3  6397952  536868863  530470912  252.9G  Linux filesystem
     ...

Verify the system partitions are all encrypted by using the following command:

     # more /etc/crypttab

Every persistent disk partition present must have an entry in the file.

If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding.'
  desc 'fix', 'To encrypt an entire partition, dedicate a partition for encryption in the partition layout.

Note: Encrypting a partition in an already-installed system is more difficult because it will need to be resized and existing partitions changed.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag gid: 'V-260484'
  tag rid: 'SV-260484r958552_rule'
  tag stig_id: 'UBTU-22-231010'
  tag fix_id: 'F-64121r953264_fix'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)']
  tag 'host'

  all_args = command('blkid').stdout.strip.split("\n").map { |s| s.sub(/^"(.*)"$/, '\1') }

  def describe_and_skip(message)
    describe message do
      skip message
    end
  end

  # TODO: This should really have a resource
  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe_and_skip('Disk Encryption and Data At Rest Implementation is handled on the Container Host')
  elsif input('data_at_rest_exempt')
    impact 0.0
    describe_and_skip('Data At Rest Requirements have been set to Not Applicable by the `data_at_rest_exempt` input.')
  elsif all_args.empty?
    # TODO: Determine if this is an NA vs and NR or even a pass
    describe_and_skip('Command blkid did not return and non-psuedo block devices.')
  else
    unencrypted_drives = all_args.reject { |a|
      a.match(/\bcrypto_LUKS\b/) ||
        input('luks_exceptions').include?(a.split(':').first) ||
        a.split(':').first.match(%r{^/dev/mapper/})
    }
    describe 'All local disk partitions' do
      it 'should be encrypted with crypto_LUKS' do
        expect(unencrypted_drives).to be_empty, "The following partitions are not encrypted with crypto_LUKS:\t\n- #{unencrypted_drives.join("\t\n- ")}"
      end
    end
  end
end
