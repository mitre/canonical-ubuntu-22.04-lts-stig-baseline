control 'SV-260538' do
  title 'Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.  
  
The session lock is implemented at the point where session activity can be determined.  
  
Regardless of where the session lock is determined and implemented, once invoked, a session lock of Ubuntu 22.04 LTS must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'Verify Ubuntu 22.04 LTS has a graphical user interface session lock configured to activate after 15 minutes of inactivity by using the following commands:   
  
Note: If no graphical user interface is installed, this requirement is not applicable. 
 
Get the following settings to verify the graphical user interface session is configured to lock the graphical user session after 15 minutes of inactivity:  
   
     $ gsettings get org.gnome.desktop.screensaver lock-enabled 
     true 
 
     $ gsettings get org.gnome.desktop.screensaver lock-delay 
     uint32 0 
 
     $ gsettings get org.gnome.desktop.session idle-delay 
     uint32 900 
 
If "lock-enabled" is not set to "true", is commented out, or is missing, this is a finding. 
 
If "lock-delay" is set to a value greater than "0", or if "idle-delay" is set to a value greater than "900", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to lock the current graphical user interface session after 15 minutes of inactivity.   
  
Set the following settings to allow graphical user interface session lock to initiate after 15 minutes of inactivity:   
  
     $ gsettings set org.gnome.desktop.screensaver lock-enabled true 
 
     $ gsettings set org.gnome.desktop.screensaver lock-delay 0 
 
     $ gsettings set org.gnome.desktop.session idle-delay 900'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-260538'
  tag rid: 'SV-260538r953427_rule'
  tag stig_id: 'UBTU-22-271025'
  tag fix_id: 'F-64175r953426_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if package('gnome-desktop3').installed?
    describe command("gsettings get org.gnome.desktop.session idle-delay | cut -d ' ' -f2") do
      its('stdout.strip') { should cmp <= input('system_inactivity_timeout') }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
