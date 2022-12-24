#!/bin/bash
Red='\033[0;31m'
Green='\033[0;32m'
Blue='\033[0;34m'
End='\033[0m'

tput clear
trap ctrl_c INT

function ctrl_c() {
        echo "**You pressed Ctrl+C...Exiting"
        exit 0;
}
#
echo '############################################'
echo '### Security Audit of your Linux machine ###'
echo '############################################'
echo ' '
echo "Let's Start...$HOSTNAME"
sleep 3
echo ' '
echo '############################################'
echo '###### General Information of System #######'
echo '############################################'
echo "Script Starts ;)"
START=$(date +%s)
echo '############################################'
echo ' '
echo -e "#$Blue 1. Linux Kernel Information$End"
echo ' '
uname -a
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 1. Kernel update is Available or not$End"
echo ' '
if [[ "$(apt list --upgradable 2>/dev/null | grep linux-image-amd64)" =~ "upgradable" ]]; then
    echo -e "Kernel Update is available $Red[Fail]$End"
else
    echo -e "No Kernel Update is available $Green[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 2. Current User and ID information$End"
echo ' '
echo 'Username:' `whoami`
echo ' '
echo 'ID information:' `id`
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 3. Linux Distribution Information$End"
echo ' '
lsb_release -a
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 4. Check Memory$End"
echo ' '
free -h
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 5. CPU/System Information$End"
echo ' '
lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 6. Check Available Space$End"
echo ' '
df -h
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 7. $HOSTNAME Up-time Information$End"
echo ' '
uptime
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 7. Check the default Shell$End"
echo ' '
readlink -f $(which sh)
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 8. List Current Logged In Users$End"
echo ' '
w
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 9. All Users List$End"
echo ' '
getent passwd "0" | cut -d: -f1
awk -F: '($3 >= 1000) {printf "%s\n",$1,$3}' /etc/passwd
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 10. BIOS related Information$End"
echo ' '
biosdecode
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo '######## Physical Security Testing #########'
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Partition Information$End"
echo ' '
lsblk
echo ' '
lsblk -f
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 13. USB Enable or not$End"
echo ' '
if [ "`stat -c '%a' /media | tail -c 2`" = 7 ]; then
  echo -e "Any User can install USB drive that can be Physical Security Loophole! $Red[Fail]$End"
else
  echo -e "Not everyone can install the USB! $Green[Pass]$End"
fi 
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 14. Verify /tmp Partition$End"
echo ' '
if mount | grep '^/tmp' | grep -q nosuid; then
echo -e "nosuid is in effect in /tmp $Green[Pass]$End"
else
echo -e "nosuid is NOT in effect in /tmp $Red[Fail]$End"
fi

if mount | grep '^/tmp' | grep -q nodev; then
echo -e "nodev is in effect in /tmp $Green[Pass]$End"
else
echo -e "nodev is NOT in effect in /tmp $Red[Fail]$End"
fi

if mount | grep '^/tmp' | grep -q noexec; then
echo -e "noexec is in effect in /tmp $Green[Pass]$End"
else
echo -e "noexec is NOT in effect in /tmp $Red[Fail]$End"
fi 
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 15. "nodev" option to /home$End"
echo ' '
if mount | grep '^/home' | grep -q nodev; then
echo -e "nodev is in effect in /home $Green[Pass]$End"
else
echo -e "nodev is NOT in effect in /home $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 15. Set sticky bit on all world-writable directories$End"
echo ' '
if [ -k "/tmp" ]; then
echo -e "Sticky-bit already set on /tmp $Green[Pass]$End"
else
echo -e "Sticky-bit is not set $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 16. Partitions and storage media$End"
echo ' '
blkid
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 17. All mounted file-systems information$End"
echo ' '
findmnt
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 18. Static file system information$End"
echo ' '
cat /etc/fstab
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo '############## System Updates ##############'
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Available Packages for Update$End"
echo ' '
apt list --upgradable 2>/dev/null
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Default Repository$End"
echo ' '
grep -v '#' /etc/apt/sources.list | sort -u
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo '########### Secure Boot Settings ###########'
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Check permission /boot/grub/grub.cfg$End"
echo ' '
if [ "`stat -c '%u' /boot/grub/grub.cfg`" = 0 ] && [ "`stat -c '%g' /boot/grub/grub.cfg`" = 0 ]
then echo -e "File 'grub.cfg' owner & group owner is root! $Green[Pass]$End"
else echo -e "File 'grub.cfg' owner & group owner is not root! $Red[Fail]$End"
fi
echo ' '
if [ "`stat -c '%a' /boot/grub/grub.cfg `" = 444 ]; then
  echo -e "Not any user can access grub.cfg file! $Green[Pass]$End"
else
  echo -e "Any user can access grub.cfg file! $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 1. Ensure bootloader password$End"
echo ' '
if [ -f "/boot/grub/user.cfg" ]; then
echo -e "Bootloader Password is set!  $Green[Pass]$End"
else
echo -e "Bootloader Password is not set!  $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 1. Check X Window system$End"
echo ' '
if [[ "$(apt list --installed 2>/dev/null | grep "xserver-xorg-core")" =~ "installed" ]]; then
    echo -e "X Window system is installed! $Red[Fail]$End"
else
    echo -e "X Window system is not installed! $Green[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Default Repository$End"
echo ' '
grep -v '#' /etc/apt/sources.list | sort -u
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo '############ Process Hardening #############'
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Restrict core dumps$End"
echo ' '
if [ "`sysctl -n fs.suid_dumpable`" = 0 ]; then
echo -e "Core Dump is restricted $Green[Pass]$End"
else
echo -e "Core Dump is not restricted $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Enable Randomized Virtual Memory Region Placement$End"
echo ' '
if [ -z "`cat /etc/sysctl.conf | grep file.kernel.randomize_va_space`" ]; then
echo -e "Randomized Virtual Memory not Enable! $Red[Fail]$End"
else
echo -e "Randomized Virtual Memory Enable! $Green[Pass]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo '############### OS Hardening ###############'
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Remove legacy services$End"
echo ' '
if [ -z "`apt list --installed 2>/dev/null | grep -E -w 'xinet|telnet|nis|tftp|rsh-server|rsh-redone-server|inetd|chargen-dgram|chargen-stream|daytime-dgram|daytime-stream|echo-dgram|echo-stream|tcpmux-server'`" ]; then
echo -e "Legacy services are not available! $Green[Pass]$End"
else
echo -e "Legacy services are available! $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Disable or remove server services that are not going to be utilized$End"
echo ' '
if [ -z "`apt list --installed 2>/dev/null | grep -E -w 'ftp|dns|dhcp|ldap|smb|nfs|samba|snmp'`" ]; then
echo -e "Services are not available! $Green[Pass]$End"
else
echo -e "Services are available, disable or remove utilities which is not required! $Red[Fail]$End $Green[Optional]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Blue 12. Ensure Daemon umask$End"
echo ' '
if [[ "$(umask)" =~ "022" ]]; then
echo -e "Umask is Good! $Green[Pass]$End"
else
echo -e "Umask is Bad! $Red[Fail]$End"
fi
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo '###### Network Security and Firewall #######'
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo 'End of Linux Audit'
echo 'For Explaination of each point, please check Audit-explain.txt file'
echo 'For Solutions to Pass the audit, please check Audit-Solution.txt file' 
echo ' '
echo '############################################'