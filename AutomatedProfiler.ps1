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

function rot13($rot13string){
    [String] $string = $null;
    $rot13string.ToCharArray() | ForEach-Object {
        if((([int] $_ -ge 97) -and ([int] $_ -le 109)) -or (([int] $_ -ge 65) -and ([int] $_ -le 77)))
        {
            $string += [char] ([int] $_ + 13);
        }
        elseif((([int] $_ -ge 110) -and ([int] $_ -le 122)) -or (([int] $_ -ge 78) -and ([int] $_ -le 90)))
        {
            $string += [char] ([int] $_ - 13);
        }
        else
        {
            $string += $_
        }
    }
    $string
}


# Variables
[string]$drive = read-host "Input the drive letter of the mounted image (ex: d:\)"
if($drive.length -ne 3){
    Write-Error -Message "The drive letter should be three digits (ex: d:\)"
}


if(-not(test-path $drive)){
    Write-Error -Message "Drive is not mounted to the filesystem"
}


$sysHive = $drive + '[root]\Windows\System32\config\system'
$softHive = $drive + '[root]\Windows\System32\config\software'
$samHive = $drive + '[root]\Windows\System32\config\sam'
$rr = ".\regripper\rip.exe"
$re = ".\RECmd\RECmd\RECmd"
$mft = ".\MFTECmd\MFTECmd.exe" 

$scriptpath = $MyInvocation.MyCommand.Path
$dir = Split-Path $scriptpath
cd $dir

write-output " "
write-host -foreground cyan "Working..."
write-output "====================================================" | out-file profiler.txt
write-output "SYSTEM INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p compname) 2>1 | select -skip 3 | out-file profiler.txt -append
$shutTime_ = (& $rr -r "$sysHive" -p shutdown) 2>1 | select -skip 6
$shutTime = $shutTime_.trim()
write-output "$shutTime" | out-file profiler.txt -append
$winn_cv = (& $rr -r "$softHive" -p winnt_cv) 2>1
$winn_cv | Foreach{$_.Trim()} | Select-Object -skip 2 | select-string currentversion, currentbuild, installdate, registeredowner, systemroot, productname, computername, registeredorganization | out-file profiler.txt -append

write-host -foreground cyan "Working..."
write-output "====================================================" | out-file profiler.txt -append
write-output "TIMEZONE INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p timezone) 2>1 | select -skip 6 | out-file profiler.txt -append

write-host -foreground cyan "Working..."
write-output "====================================================" | out-file profiler.txt -append
write-output "NETWORKING INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p nic2) 2>1 | select -skip 2 | out-file profiler.txt -append
(& $rr -r "$sysHive" -p network) 2>1 | select -skip 3 | out-file profiler.txt -append
write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
write-output "NETWORK LIST" | out-file profiler.txt -append
write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
(& $rr -r "$softHive" -p networklist) 2>1 | select -skip 3 | out-file profiler.txt -append

write-host -foreground cyan "Working..."
write-output "====================================================" | out-file profiler.txt -append
write-output "FIREWALL DETAILS" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p fw_config) 2>1 | select -skip 3 | out-file profiler.txt -append

# Persistent routes
write-output "====================================================" | out-file profiler.txt -append
write-output "PERSISTENT ROUTES" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$softHive" -p routes) 2>1 | out-file profiler.txt -append

# Gets User info from SAM hive
write-output "====================================================" | out-file profiler.txt -append
write-output "LOCAL USER AND GROUP INFORMATION" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$samHive" -p samparse) 2>1 | select -skip 3 | out-file profiler.txt -append

write-host -foreground cyan "Working..."
write-output "====================================================" | out-file profiler.txt -append
write-output "AUTORUNS" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
$run = .\RECmd\RECmd\RECmd --hive $softHive --keyname microsoft\windows\currentversion\run | select -skip 19
$run = (& $re --hive "$softHive" --keyname microsoft\windows\currentversion\run) | select -skip 19
$run[0..($run.count - 2)] | out-file profiler.txt -append

$run = (& $re --hive "$softHive" --keyname microsoft\windows\currentversion\runonce) | select -skip 19 
$run[0..($run.count - 5)] | out-file profiler.txt -append

$run = (& $re --hive "$softHive" --keyname microsoft\windows\currentversion\explorer\shellexecutehooks) | select -skip 19 
$run[0..($run.count - 5)] | out-file profiler.txt -append

$run = (& $re --hive "$softHive" --keyname classes\protocols\filter\application/octet-stream) | select -skip 19 
$run[0..($run.count - 3)] | out-file profiler.txt -append

$run = (& $re --hive "$softHive" --keyname classes\protocols\filter\application/x-complus) | select -skip 19 
$run[0..($run.count - 3)] | out-file profiler.txt -append

$run = (& $re --hive "$softHive" --keyname classes\protocols\filter\application/x-msdownload) | select -skip 19 
$run[0..($run.count - 3)] | out-file profiler.txt -append

# Winlogon
write-output "====================================================" | out-file profiler.txt -append
write-output "WINLOGON" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
$win = (& $rr -r "$softHive" -p winlogon) 2>1 | select -skip 3
$win[0..($win.count - 3)] | out-file profiler.txt -append

write-host -foreground cyan "Working..."
write-output "====================================================" | out-file profiler.txt -append
write-output "USB MASS STORAGE DEVICE HISTORY" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p usb) 2>1 | select -skip 3 | out-file profiler.txt -append
(& $rr -r "$sysHive" -p usbdevices) 2>1 | select -skip 3 | out-file profiler.txt -append
(& $rr -r "$sysHive" -p usbstor) 2>1 | select -skip 3 | out-file profiler.txt -append

# SERVICES STARTING AT BOOT (START KEY = 2)
write-output "====================================================" | out-file profiler.txt -append
write-output "SERVICES STARTING AT BOOT (START KEY = 2)" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p services) 2>1 | select -skip 3 | out-file profiler.txt -append

write-host -foreground cyan "Working..."
write-output "LIST OF DRIVERS" | out-file profiler.txt -append
write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
(& $rr -r "$sysHive" -p drivers32) 2>1 | select -skip 3 | out-file profiler.txt -append

# INSTALLED EXEs (APP_PATHS KEY)
write-output "====================================================" | out-file profiler.txt -append
write-output "INSTALLED EXES (APP_PATHS KEY)" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$softHive" -p apppaths) 2>1 | select -skip 3 | out-file profiler.txt -append

# INSTALLED APPLICATIONS (UNINSTALL KEY)
write-output "====================================================" | out-file profiler.txt -append
write-output "INSTALLED APPLICATIONS (UNINSTALL KEY)" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$soft_hive" -p uninstall) 2>1 | select -skip 3 | out-file profiler.txt -append

# USER DETAILS
## AUTORUNS
# The straightforward method to do this was returning $null; workaround implemented
$cur_pwd = $pwd
cd $drive
cd '.\`[root`]'
cd '.\users'
$cur_pwd2 = $pwd
$userlist = (Get-ChildItem .\*\NTUSER.DAT).FullName
cd $cur_pwd

write-host -foreground cyan "Working..."
foreach ($user in $userlist)
{
    write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
    write-output "$user USER DETAILS" | out-file profiler.txt -append
    write-output "=-=-=-=-=-=-=-=-=-=-=-=-=-=" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    write-output "AUTORUNS" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    (& $re --hive "$user" --keyname software\microsoft\windows\currentversion\run) | select -skip 19 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    write-output "MRU KEYS" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append   
    (& $re --hive "$user" --keyname software\microsoft\windows\currentversion\explorer\runmru) | select -skip 19 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append
    write-output "MRU KEYS" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append   
    (& $re --hive "$user" --keyname software\microsoft\windows\currentversion\explorer\runmru) | select -skip 19 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append


    write-output "====================================================" | out-file profiler.txt -append  
    write-output "MAPPED DRIVES" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append 
    (& $re --hive "$user" --keyname network)  | select -skip 24 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append

    write-output "====================================================" | out-file profiler.txt -append  
    write-output "TYPEDPATHs" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append 
    (& $re --hive "$user" --keyname software\microsoft\windows\currentversion\explorer\typedpaths) | select -skip 17 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append

    write-output "====================================================" | out-file profiler.txt -append  
    write-output "TYPEDURLs" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append 
    (& $re --hive "$user" --keyname software\microsoft\Software\Microsoft\InternetExplorer\TypedURLs) | select -skip 17 | out-file profiler.txt -append
    write-output " " | out-file profiler.txt -append


    write-output "====================================================" | out-file profiler.txt -append  
    write-output "USERASSIST" | out-file profiler.txt -append
    write-output "====================================================" | out-file profiler.txt -append 
        $a = (& $re --hive "$user" --keyname software\microsoft\windows\currentversion\explorer\userassist)
        $b = $a | sls "name: {"

        foreach($c in $b){
            $d = $c -split " "
            $guid += @($d[1])
        }

        foreach($guid_ in $guid){
            $aa = (& $re --hive "$user" --keyname software\microsoft\windows\currentversion\explorer\userassist\$guid_\count)
            Write-Output " " | out-file profiler.txt -append
            $aa[20..21] | out-file profiler.txt -append
            Write-Output " " | out-file profiler.txt -append
            $s_name = $aa | sls "name: {"
            foreach($name in $s_name){
                $n = $name -split " "
                $n = (($n[1])).TrimStart("{")
                rot13 $n | out-file profiler.txt -append
            }    
        }
        Remove-Variable guid -ErrorAction SilentlyContinue
        write-output " " | out-file profiler.txt -append
}

write-host -foreground cyan "Working..."
# VARIOUS MALWARE
write-output "====================================================" | out-file profiler.txt -append
write-output "OTHER MALWARE LOCATIONS" | out-file profiler.txt -append
write-output "====================================================" | out-file profiler.txt -append
(& $rr -r "$softHive" -p malware) 2>1 | out-file profiler.txt -append
(& $rr -r "$softHive" -p malware) 2>1 | out-file profiler.txt -append

# The straightforward method to do this was returning $null; workaround implemented
cd $drive
cd '.\`[root`]'
Copy-Item `$mft $cur_pwd
cd $cur_pwd

write-host -foreground cyan "Working..."
(& $mft -f '.\$mft' --csv ".\" --csvf mft.csv)  2>1 | out-null
Remove-Item '.\$mft'; remove-item .\1
