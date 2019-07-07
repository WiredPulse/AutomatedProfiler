<#
    .SYNOPSIS  
        This script will profile an image utilizing RegRipper, RECmd, and various PowerShell cmdlets. The output will be in a text file 
        called 'profiler.txt' and will contain information about said system such as system info, networking settings, firewall details, 
        user data, autorun, service, and mru keys. The returned data will not provide you everything you need to do forensics on the image 
        but it will present a lot of the data that you would find yourself looking for.

	    In order for this script to work, it will need to be in the same directory with the other directories (RegRipper, RECmd, and plugins) 
        it was downloaded with.

        The profiler script will parse a mounted image utilizing RegRipper, RECmd, and various PowerShell cmdlets. The output of the script 
        will be in a text file called 'profiler.txt' and will contain information about said system such as system info, networking settings, 
        firewall details, user data, autorun, service, and mru keys. The returned data will not provide you everything you need to do forensics 
        on the image but it will present a lot of the data that you would find yourself looking for.

        In order for this script to work, it will need to be in the same directory with the other supporting directories (RegRipper, RECmd, and 
        plugins) that are included. A mounted image also needs to be available through FTK Imager.


    .NOTES  
        File Name      : profiler.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell v2
        Created        : 06 July 16

    .USAGE
        1) Mount an image using FTK Imager. 
        2) Take note of the drive letter assigned to the mounted image. 
        3) Download this repository. 
        4) Unzip the contents of the zip. 
        5) Verify that a folder called ‘AutomatedProfiler-master’ is what was unzipped.
        6) In PowerShell, navigate to the AutomatedProfiler-master directory and type '.\profiler.ps1'. 
        7) When prompted, input the drive letter assigned to the image.
        8) Analyze the profiler.txt file once the script completes.
    #>	

# Variables
$drive_letter = read-host "Input the drive letter of the attached drive with the Registry hives (example - e:\)"
$sys_hive = $drive_letter + '[root]\Windows\System32\config\system'
$soft_hive = $drive_letter + '[root]\Windows\System32\config\software'
$sam_hive = $drive_letter + '[root]\Windows\System32\config\sam'

# SYSTEM INFORMATION
write-output "====================================================" | out-file profiler.txt
write-output "SYSTEM INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p compname 2>1 | select -skip 3 | out-file profiler.txt -append
$shut_time = .\regripper\rip.exe -r $sys_hive -p shutdown 2>1 | select -skip 6
$shut_time2 = $shut_time.trim()
write-output "$shut_time2" | out-file profiler.txt -append
.\regripper\rip.exe -r $soft_hive -p winnt_cv 2>1 > winnt_cv.txt
$prod_info = Get-Content .\winnt_cv.txt 
$prod_info | Foreach {$_.Trim()} | Set-Content winnt_cv.txt
get-content winnt_cv.txt |  select -skip 2 | select-string currentversion, currentbuild, installdate, registeredowner, systemroot, productname, computername, registeredorganization | out-file profiler.txt -append
remove-item .\winnt_cv.txt

# TIMEZONE INFORMATION
write-output "====================================================" | out-file profiler.txt -append
write-output "TIMEZONE INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p timezone 2>1 | select -skip 6 | out-file profiler.txt -append

# NETWORKING INFORMATION
write-output "====================================================" | out-file profiler.txt -append
write-output "NETWORKING INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p nic2 2>1 | select -skip 2 | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p network 2>1 | select -skip 3 | out-file profiler.txt -append
write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
write-output "NETWORK LIST" | out-file profiler.txt -append
write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
.\regripper\rip.exe -r $soft_hive -p networklist 2>1 | select -skip 3 | out-file profiler.txt -append

# Firewall details
write-output "====================================================" | out-file profiler.txt -append
write-output "FIREWALL DETAILS" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p fw_config 2>1 | select -skip 3 | out-file profiler.txt -append

# Persistent routes
write-output "====================================================" | out-file profiler.txt -append
write-output "PERSISTENT ROUTES" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $soft_hive -p routes 2>1 | out-file profiler.txt -append

# Gets User info from SAM hive
write-output "====================================================" | out-file profiler.txt -append
write-output "LOCAL USER AND GROUP INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sam_hive -p samparse 2>1 | select -skip 3 | out-file profiler.txt -append

# Gets Autoruns
write-output "====================================================" | out-file profiler.txt -append
write-output "AUTORUNS" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname microsoft\windows\currentversion\run | select -skip 19
$run2 = $run[0..($run.count - 2)] 
$run2  | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname microsoft\windows\currentversion\runonce | select -skip 19 
$run2 = $run[0..($run.count - 5)] 
$run2  | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname microsoft\windows\currentversion\explorer\shellexecutehooks | select -skip 19 
$run2 = $run[0..($run.count - 5)] 
$run2  | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname classes\protocols\filter\application/octet-stream | select -skip 19 
$run2 = $run[0..($run.count - 3)] 
$run2  | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname classes\protocols\filter\application/x-complus | select -skip 19 
$run2 = $run[0..($run.count - 3)] 
$run2  | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname classes\protocols\filter\application/x-msdownload | select -skip 19 
$run2 = $run[0..($run.count - 3)] 
$run2  | out-file profiler.txt -append

# Winlogon
write-output "====================================================" | out-file profiler.txt -append
write-output "WINLOGON" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
$win = .\regripper\rip.exe -r $soft_hive -p winlogon 2>1 | select -skip 3
$win2 = $win[0..($win.count - 3)] 
$win2  | out-file profiler.txt -append

# USB MASS STORAGE DEVICE HISTORY
write-output "====================================================" | out-file profiler.txt -append
write-output "USB MASS STORAGE DEVICE HISTORY" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p usb 2>1 | select -skip 3 | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p usbdevices 2>1 | select -skip 3 | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p usbstor 2>1 | select -skip 3 | out-file profiler.txt -append

# SERVICES STARTING AT BOOT (START KEY = 2)
write-output "====================================================" | out-file profiler.txt -append
write-output "SERVICES STARTING AT BOOT (START KEY = 2)" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p services 2>1 | select -skip 3 | out-file profiler.txt -append

# LIST OR DRIVERS
write-output "LIST OF DRIVERS" | out-file profiler.txt -append
write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p drivers32 2>1 | select -skip 3 | out-file profiler.txt -append

# INSTALLED EXEs (APP_PATHS KEY)
write-output "====================================================" | out-file profiler.txt -append
write-output "INSTALLED EXES (APP_PATHS KEY)" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $soft_hive -p apppaths 2>1 | select -skip 3 | out-file profiler.txt -append

# INSTALLED APPLICATIONS (UNINSTALL KEY)
write-output "====================================================" | out-file profiler.txt -append
write-output "INSTALLED APPLICATIONS (UNINSTALL KEY)" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $soft_hive -p uninstall 2>1 | select -skip 3 | out-file profiler.txt -append

# USER DETAILS
## AUTORUNS
$cur_pwd = $pwd
cd $drive_letter
cd '.\`[root`]'
cd '.\users'
$cur_pwd2 = $pwd
$userlist = Get-ChildItem
cd $cur_pwd

foreach ($user in $userlist)
{
    write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
    write-output "$user USER DETAILS" | out-file profiler.txt -append
    write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    write-output "AUTORUNS" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    .\RECmd\RECmd\RECmd.exe --hive $cur_pwd2\$user\NTUSER.DAT --keyname software\microsoft\windows\currentversion\run | select -skip 8 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    write-output "MRU KEYS" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append   
    .\RECmd\RECmd\RECmd.exe --hive $cur_pwd2\$user\NTUSER.DAT --keyname software\microsoft\windows\currentversion\explorer\runmru | select -skip 8 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append
}

# VARIOUS MALWARE
write-output "====================================================" | out-file profiler.txt -append
write-output "OTHER MALWARE LOCATIONS" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
.\regripper\rip.exe -r $soft_hive -p malware 2>1 | out-file profiler.txt -append
.\regripper\rip.exe -r $sys_hive -p malware 2>1 | out-file profiler.txt -append




