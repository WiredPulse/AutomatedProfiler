<#
    .SYNOPSIS  
        This script will profile an image utilizing RegRipper, RECmd, and various PowerShell cmdlets. The output will be 		in a text file called 'profiler.txt' and will contain information about said system such as system info, 			networking settings, firewall details, user data, autorun, service, and mru keys. The returned data will not 			provide you everything you need to do forensics on the image but it will present a lot of the data that you would 	find yourself looking for.

	In order for this script to work, it will need to be in the same directory with the other directories (RegRipper, 	RECmd, and plugins) it was downloaded with.

The profiler script will parse a mounted image utilizing RegRipper, RECmd, and various PowerShell cmdlets. The output of the script will be in a text file called 'profiler.txt' and will contain information about said system such as system info, networking settings, firewall details, user data, autorun, service, and mru keys. The returned data will not provide you everything you need to do forensics on the image but it will present a lot of the data that you would find yourself looking for.

In order for this script to work, it will need to be in the same directory with the other supporting directories (RegRipper, RECmd, and plugins) that are included. A mounted image also needs to be available through FTK Imager.

    .NOTES  
        File Name      : profiler.ps1
        Version        : v.0.1  
        Author         : CW3 Tomlinson, Fernando
        Email          : fernando.c.tomlinson2.mil@mail.mil
        Prerequisite   : PowerShell v2
        Created        : 06 July 16

    .USAGE
	1) Mount an image using FTK Imager.
	2) Take note of the drive letter assigned to the mounted image.
	3) Navigate to the Profile directory and type '.\profiler.ps1'
    #>	

# Variables
$drive_letter = read-host "Input drive letter of the attached drive with Registry hives (example - e:\)"
$sys_hive = $drive_letter + '[root]\Windows\System32\config\system'
$soft_hive = $drive_letter + '[root]\Windows\System32\config\software'
$sam_hive = $drive_letter + '[root]\Windows\System32\config\sam'

# SYSTEM INFORMATION
echo "====================================================" >> profiler.txt
echo "SYSTEM INFORMATION" > profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p compname 2>1 | select -skip 3 >> profiler.txt
$shut_time = .\regripper\rip.exe -r $sys_hive -p shutdown 2>1 | select -skip 6
$shut_time2 = $shut_time.trim()
echo "$shut_time2" >> profiler.txt
.\regripper\rip.exe -r $soft_hive -p winnt_cv 2>1 > winnt_cv.txt
$prod_info = Get-Content .\winnt_cv.txt 
$prod_info | Foreach {$_.Trim()} | Set-Content winnt_cv.txt
get-content winnt_cv.txt |  select -skip 2 | select-string currentversion, currentbuild, installdate, registeredowner, systemroot, productname, computername, registeredorganization >> profiler.txt
remove-item .\winnt_cv.txt
#(gc profiler.txt) | ? {$_.trim() -ne "" } | set-content profiler.txt

# TIMEZONE INFORMATION
echo "====================================================" >> profiler.txt
echo "TIMEZONE INFORMATION" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p timezone 2>1 | select -skip 6 >> profiler.txt

# NETWORKING INFORMATION
echo "====================================================" >> profiler.txt
echo "NETWORKING INFORMATION" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p nic2 2>1 | select -skip 2 >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p network 2>1 | select -skip 3 >> profiler.txt
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> profiler.txt
echo "NETWORK LIST" >> profiler.txt
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> profiler.txt
.\regripper\rip.exe -r $soft_hive -p networklist 2>1 | select -skip 3 >> profiler.txt

# Firewall details
echo "====================================================" >> profiler.txt
echo "FIREWALL DETAILS" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p fw_config 2>1 | select -skip 3 >> profiler.txt

# Persistent routes
echo "====================================================" >> profiler.txt
echo "PERSISTENT ROUTES" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $soft_hive -p routes 2>1 >> profiler.txt

# Gets User info from SAM hive
echo "====================================================" >> profiler.txt
echo "LOCAL USER AND GROUP INFORMATION" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sam_hive -p samparse 2>1 | select -skip 3 >> profiler.txt

# Gets Autoruns
echo "====================================================" >> profiler.txt
echo "AUTORUNS" >> profiler.txt
echo "====================================================" >> profiler.txt
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname microsoft\windows\currentversion\run | select -skip 19
$run2 = $run[0..($run.count - 2)] 
$run2  >> profiler.txt
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname microsoft\windows\currentversion\runonce | select -skip 19 
$run2 = $run[0..($run.count - 5)] 
$run2  >> profiler.txt
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname microsoft\windows\currentversion\explorer\shellexecutehooks | select -skip 19 
$run2 = $run[0..($run.count - 5)] 
$run2  >> profiler.txt
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname classes\protocols\filter\application/octet-stream | select -skip 19 
$run2 = $run[0..($run.count - 3)] 
$run2  >> profiler.txt
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname classes\protocols\filter\application/x-complus | select -skip 19 
$run2 = $run[0..($run.count - 3)] 
$run2  >> profiler.txt
$run = .\RECmd\RECmd\RECmd --hive $soft_hive --keyname classes\protocols\filter\application/x-msdownload | select -skip 19 
$run2 = $run[0..($run.count - 3)] 
$run2  >> profiler.txt

# Winlogon
echo "====================================================" >> profiler.txt
echo "WINLOGON" >> profiler.txt
echo "====================================================" >> profiler.txt
$win = .\regripper\rip.exe -r $soft_hive -p winlogon 2>1 | select -skip 3
$win2 = $win[0..($win.count - 3)] 
$win2  >> profiler.txt

# USB MASS STORAGE DEVICE HISTORY
echo "====================================================" >> profiler.txt
echo "USB MASS STORAGE DEVICE HISTORY" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p usb 2>1 | select -skip 3 >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p usbdevices 2>1 | select -skip 3 >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p usbstor 2>1 | select -skip 3 >> profiler.txt

# SERVICES STARTING AT BOOT (START KEY = 2)
echo "====================================================" >> profiler.txt
echo "SERVICES STARTING AT BOOT (START KEY = 2)" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p services 2>1 | select -skip 3 >> profiler.txt

# LIST OR DRIVERS
echo "LIST OF DRIVERS" >> profiler.txt
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p drivers32 2>1 | select -skip 3 >> profiler.txt

# INSTALLED EXEs (APP_PATHS KEY)
echo "====================================================" >> profiler.txt
echo "INSTALLED EXES (APP_PATHS KEY)" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $soft_hive -p apppaths 2>1 | select -skip 3 >> profiler.txt

# INSTALLED APPLICATIONS (UNINSTALL KEY)
echo "====================================================" >> profiler.txt
echo "INSTALLED APPLICATIONS (UNINSTALL KEY)" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r c:\users\sansforensics408\Desktop\Software -p uninstall 2>1 | select -skip 3 >> profiler.txt

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
    echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> profiler.txt
    echo "$user USER DETAILS" >> profiler.txt
    echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> profiler.txt
    echo "====================================================" >> profiler.txt
    echo "AUTORUNS" >> profiler.txt
    echo "====================================================" >> profiler.txt
    .\RECmd\RECmd\RECmd.exe --hive $cur_pwd2\$user\NTUSER.DAT --keyname software\microsoft\windows\currentversion\run | select -skip 8 >> profiler.txt
    echo " " >> profiler.txt
    echo "====================================================" >> profiler.txt
    echo "MRU KEYS" >> profiler.txt
    echo "====================================================" >> profiler.txt   
    .\RECmd\RECmd\RECmd.exe --hive $cur_pwd2\$user\NTUSER.DAT --keyname software\microsoft\windows\currentversion\explorer\runmru | select -skip 8 >> profiler.txt
    echo " " >> profiler.txt
}

# VARIOUS MALWARE
echo "====================================================" >> profiler.txt
echo "OTHER MALWARE LOCATIONS" >> profiler.txt
echo "====================================================" >> profiler.txt
.\regripper\rip.exe -r $soft_hive -p malware 2>1 >> profiler.txt
.\regripper\rip.exe -r $sys_hive -p malware 2>1 >> profiler.txt

remove-item .\1



