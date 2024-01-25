#!/bin/bash
Red='\033[0;31m'
Green='\033[0;32m'
Blue='\033[0;34m'
Yellow='\033[0;33m'
End='\033[0m'

tput clear
trap ctrl_c INT

function ctrl_c() {
        echo "**You pressed Ctrl+C...Exiting"
        exit 0;
}
#
cat << "EOF"
  _      _                                      _ _ _   _             
 | |    (_)                      /\            | (_) | (_)            
 | |     _ _ __  _   ___  __    /  \  _   _  __| |_| |_ _ _ __   __ _ 
 | |    | | '_ \| | | \ \/ /   / /\ \| | | |/ _` | | __| | '_ \ / _` |
 | |____| | | | | |_| |>  <   / ____ \ |_| | (_| | | |_| | | | | (_| |
 |______|_|_| |_|\__,_/_/\_\ /_/    \_\__,_|\__,_|_|\__|_|_| |_|\__, |
                                                                 __/ |
                                                                |___/ 
  Created by Bhaskar Soni, Github: Github.com/Bhaskar-soni  
EOF
#
echo '############################################'
echo -e "###$Blue Security Audit of your Linux machine$End ###"
echo '############################################'
echo ' '
echo "Let's Start...$HOSTNAME"
sleep 3
echo ' '
echo '############################################'
echo -e "#######$Blue General Information of System$End ######"
echo '############################################'
echo "Script Starts ;)"
START=$(date +%s)
echo '############################################'
echo ' '
echo -e "#$Yellow 1. Linux Kernel Information$End"
echo ' '
uname -a
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 2. Kernel update is Available or not$End"
echo ' '
# Check if a kernel update is available
if [ "$(yum check-update kernel | grep -c 'kernel.')" -eq 0 ]; then
    echo "$Green[Pass]$End No kernel update is available!"
else
    echo "$Red[Fail]$End A kernel update is available!"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 3. Current User and ID information$End"
echo ' '
echo 'Username:' `whoami`
echo ' '
echo 'ID information:' `id`
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 4. Linux Distribution Information$End"
echo ' '
lsb_release -a
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 5. Check Memory$End"
echo ' '
free -h
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 6. CPU/System Information$End"
echo ' '
lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 7. Check Available Space$End"
echo ' '
df -h
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 8. $HOSTNAME Up-time Information$End"
echo ' '
uptime
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 9. Check the default Shell$End"
echo ' '
readlink -f $(which sh)
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 10. List Current Logged In Users$End"
echo ' '
w
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 11. All Users List$End"
echo ' '
getent passwd "0" | cut -d: -f1
awk -F: '($3 >= 1000) {printf "%s\n",$1,$3}' /etc/passwd
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 12. BIOS related Information$End"
echo ' '
biosdecode
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "########$Blue Physical Security Testing$End #########"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 13. Partition Information$End"
echo ' '
lsblk
echo ' '
lsblk -f
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 14. USB Enable or not$End"
echo ' '
# Check if user is root
if [ "$(id -u)" != "0" ]; then
    echo "$Red[Error]$End You must be root to run this script"
fi
# Search for all users with console access
users=$(who | awk '{print $1}' | sort | uniq)
# Loop through each user and check for USB access
for user in $users; do
    # Check if user has permission to access USB devices
    if [ $(sudo -u $user ls /dev/sda1 2>/dev/null) ]; then
        echo -e "$Red[Fail]$End User $user has permission to plug in a USB device"
    fi
done
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 15. Check nodev, nosuid, and noexec options on /tmp $End"
echo ' '
# Check if /tmp is a separate partition
if ! mount | grep "on /tmp " | grep -q "/dev/"; then
    echo -e "$Red[Error]$End /tmp is not a separate partition"
fi
# Check if nodev, nosuid, and noexec options are set on /tmp
if mount | grep "on /tmp " | grep -q "nodev,nosuid,noexec"; then
    echo -e "$Green[Pass]$End nodev, nosuid, and noexec options are set on /tmp"
else
    echo -e "$Red[Error]$End nodev, nosuid, and noexec options are not set on /tmp"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 16. 'nodev' option to /home$End"
echo ' '
if mount | grep '^/home' | grep -q nodev; then
echo -e "$Green[Pass]$End nodev is in effect in /home"
else
echo -e "$Red[Fail]$End nodev is NOT in effect in /home"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 17. Set sticky bit on all world-writable directories$End"
echo ' '
# Check if /tmp is a separate partition
if ! mount | grep "on /tmp " | grep -q "/dev/"; then
    echo "$Red[Error]$End /tmp is not a separate partition"
fi
# Check if the sticky bit is set on /tmp
if [ "$(stat -c %a /tmp)" -eq 1777 ]; then
    echo "$Green[Pass]$End The sticky bit is set on /tmp"
else
    echo "$Red[Error]$End The sticky bit is not set on /tmp"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 18. Partitions and storage media$End"
echo ' '
blkid
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 19. All mounted file-systems information$End"
echo ' '
findmnt
echo ' '
echo '############################################'
echo ' '
echo -e "##$Yellow 20. Static file system information$End"
echo ' '
cat /etc/fstab
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "##############$Blue System Updates$End ##############"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 21. Available Packages for Update$End"
echo ' '
yum check-update > Upgradable_packages_list.txt > /dev/null
yum check-update | wc -l
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 22. List of Repositories $End"
echo ' '
yum repolist | awk '/^repo id/ {flag=1; next} /^\s*$/ {flag=0} flag {print $1}'
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "###########$Blue Secure Boot Settings$End ###########"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 23. Check permission /boot/grub/grub.cfg$End"
echo ' '
if [ "`stat -c '%u' /boot/grub/grub.cfg`" = 0 ] && [ "`stat -c '%g' /boot/grub/grub.cfg`" = 0 ]
then echo -e "$Green[Pass]$End File 'grub.cfg' owner & group owner is root! "
else echo -e "$Red[Fail]$End File 'grub.cfg' owner & group owner is not root! "
fi
echo ' '
if [ "`stat -c '%a' /boot/grub/grub.cfg `" = 444 ]; then
  echo -e "$Green[Pass]$End Not any user can access grub.cfg file!"
else
  echo -e "$Red[Fail]$End Any user can access grub.cfg file! "
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 24. Ensure bootloader password$End"
echo ' '
if [ -f "/boot/grub/user.cfg" ]; then
echo -e "$Green[Pass]$End Bootloader Password is set!"
else
echo -e "$Red[Fail]$End Bootloader Password is not set!"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 25. Check X Window system$End"
echo ' '
# Check if X Window system is installed
if rpm -q xorg-x11-server-Xorg &>/dev/null; then
    echo "$Red[Fail]$End X Window system is installed"
else
    echo "$Green[Pass]$End X Window system is not installed"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 26. Default Repository$End"
echo ' '
yum repolist enabled | grep -w 'base' | awk '{print $1}'
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "############$Blue Process Hardening$End #############"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 27. Restrict core dumps$End"
echo ' '
if [ "`sysctl -n fs.suid_dumpable`" = 0 ]; then
echo -e "$Green[Pass]$End Core Dump is restricted"
else
echo -e "$Red[Fail]$End Core Dump is not restricted"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 28. Enable Randomized Virtual Memory Region Placement$End"
echo ' '
if [ -z "`cat /etc/sysctl.conf | grep file.kernel.randomize_va_space`" ]; then
echo -e "$Red[Fail]$End Randomized Virtual Memory not Enable!"
else
echo -e "$Green[Pass]$End Randomized Virtual Memory Enable!"
fi
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "###############$Blue OS Hardening$End ###############"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 29. Remove legacy services$End"
echo ' '
if [ -z "`yum list installed 2>/dev/null | grep -E -w 'xinetd|telnet-server|ypserv|tftp-server|rsh-server|rsh|rsh-redone-server|inetd|chargen-stream|daytime-dgram|daytime-stream|echo-dgram|echo-stream|tcpmux-server'`" ]; then
    echo -e "$Green[Pass]$End Legacy services are not available!"
else
    echo -e "$Red[Fail]$End Legacy services are available!"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 30. Disable or remove server services that are not going to be utilized$End"
echo ' '
if [ -z "`yum list installed 2>/dev/null | grep -E -w 'vsftpd|bind|dhcp|openldap-servers|samba|nfs-utils|net-snmp'`" ]; then
    echo -e "$Green[Pass]$End Services are not available!"
else
    echo -e "$Red[Fail]$End $Green[Optional]$End Services are available, disable or remove utilities which is not required!"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 31. Remove xinetd, if possible$End"
echo ' '
if rpm -q xinetd >/dev/null 2>&1; then
    echo "$Red[Fail]$End xinetd is installed."
else
    echo "$Green[Pass]$End xinetd is not installed."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 32. Check Legacy services (e.g., chargen-dgram, chargen-stream, daytime-dgram, daytime-stream, echo-dgram, echo-stream, tcpmux-server)$End"
echo ' '
services=("chargen-dgram" "chargen-stream" "daytime-dgram" "daytime-stream" "echo-dgram" "echo-stream" "tcpmux-server")
# Loop through services
for service in "${services[@]}"; do
    # Check service status
    status=$(systemctl is-active $service 2>&1)
    if [ $? -eq 0 ]; then
        echo "$service is $status"
    else
        echo "Failed to get status of $service: $status"
    fi
done
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 33. Check services that are not going to be utilized (e.g., FTP, DNS, LDAP, SMB, DHCP, NFS, SNMP, etc.)$End"
echo ' '
utilities=("vsftpd" "named" "slapd" "smb" "dhcpd" "nfs" "snmpd")
echo "Checking status of services..."
running_services=0
stopped_services=0
# Loop through services
for service in "${utilities[@]}"; do
    # Check service status
    if systemctl is-active $service >/dev/null 2>&1; then
        echo "$Red[Fail]$End $service is running"
        ((running_services++))
    else
        echo "$Green[Pass]$End $service is not running"
        ((stopped_services++))
    fi
done
echo "Summary: $running_services services are running, $stopped_services services are not running."
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 34. Ensure Daemon umask$End"
echo ' '
if [[ "$(umask)" =~ "022" ]]; then
echo -e "$Green[Pass]$End Umask is Good!"
else
echo -e "$Red[Fail]$End Umask is Bad!"
fi
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "###### $Blue Network Security and Firewall$End ######"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 35. Disable IP forwarding.$End"
echo ' '
# Check if IP forwarding is enabled
ip_forward=$(sysctl -n net.ipv4.ip_forward)

if [ "$ip_forward" -eq 1 ]; then
    echo "$Red[Fail]$End IP forwarding is enabled."
else
    echo "$Green[Pass]$End IP forwarding is disabled."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 36. Disable send packet redirects.$End"
echo ' '
# Check if packet redirects are being sent
send_redirects_all=$(sysctl -n net.ipv4.conf.all.send_redirects)
send_redirects_default=$(sysctl -n net.ipv4.conf.default.send_redirects)

if [ "$send_redirects_all" -eq 0 ] && [ "$send_redirects_default" -eq 0 ]; then
    echo "$Green[Pass]$End Packet redirects are not being sent."
else
    echo "$Red[Fail]$End Packet redirects are being sent."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 37. Disable source routed packet acceptance. $End"
echo ' '
# Check if source routed packets are being accepted
accept_source_route_all=$(sysctl -n net.ipv4.conf.all.accept_source_route)
accept_source_route_default=$(sysctl -n net.ipv4.conf.default.accept_source_route)

if [ "$accept_source_route_all" -eq 0 ] && [ "$accept_source_route_default" -eq 0 ]; then
    echo "$Green[Pass]$End Source routed packets are not being accepted."
else
    echo "$Red[Fail]$End Source routed packets are being accepted."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 38. Disable ICMP redirect acceptance. $End"
echo ' '
# Check if ICMP redirects are being accepted
accept_redirects_all=$(sysctl -n net.ipv4.conf.all.accept_redirects)
accept_redirects_default=$(sysctl -n net.ipv4.conf.default.accept_redirects)

if [ "$accept_redirects_all" -eq 0 ] && [ "$accept_redirects_default" -eq 0 ]; then
    echo "$Green[Pass]$End ICMP redirects are not being accepted."
else
    echo "$Red[Fail]$End ICMP redirects are being accepted."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 39. Enable Ignore Broadcast Requests $End"
echo ' '
# Check if broadcast requests are being accepted
ignore_broadcasts=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)

if [ "$ignore_broadcasts" -eq 0 ]; then
    echo "$Red[Fail]$End Broadcast requests are being accepted."
else
    echo "$Green[Pass]$End Broadcast requests are not being accepted."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 40. Enable Bad Error Message Protection. $End"
echo ' '
# Check if bad error message protection is enabled
ignore_bogus=$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses)

if [ "$ignore_bogus" -eq 1 ]; then
    echo "$Green[Pass]$End Bad error message protection is enabled."
else
    echo "$Red[Fail]$End Bad error message protection is not enabled."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 41. Enable TCP/SYN cookies. $End"
echo ' '
# Check if TCP SYN cookies are enabled
syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies)

if [ "$syn_cookies" -eq 1 ]; then
    echo "$Green[Pass]$End TCP SYN cookies are enabled."
else
    echo "$Red[Fail]$End TCP SYN cookies are not enabled."
fi
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "###### $Blue Remote Administration via SSH$End ######"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 42. Set SSH protocol to 2. $End"
echo ' '
# Check if SSH protocol 2 is set
ssh_protocol=$(grep "^Protocol" /etc/ssh/sshd_config | awk '{print $2}')

if [ "$ssh_protocol" == "2" ]; then
    echo "$Green[Pass]$End SSH protocol 2 is set."
else
    echo "$Red[Fail]$End SSH protocol 2 is not set."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 43. Set SSH LogLevel to INFO. $End"
echo ' '
# Check if SSH LogLevel is set to INFO
ssh_loglevel=$(grep "^LogLevel" /etc/ssh/sshd_config | awk '{print $2}')

if [ "$ssh_loglevel" == "INFO" ]; then
    echo "$Green[Pass]$End SSH LogLevel is set to INFO."
else
    echo "$Red[Fail]$End SSH LogLevel is not set to INFO."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 44. Disable SSH Root login. $End"
echo ' '
# Check if SSH root login is disabled
root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')

if [ "$root_login" == "no" ]; then
    echo "$Green[Pass]$End SSH root login is disabled."
else
    echo "$Red[Fail]$End SSH root login is not disabled."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 45. Set SSH PermitEmptyPasswords to No. $End"
echo ' '
# Check if SSH PermitEmptyPasswords is set to No
empty_passwords=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{print $2}')

if [ "$empty_passwords" == "no" ]; then
    echo "$Green[Pass]$End SSH PermitEmptyPasswords is set to No."
else
    echo "$Red[Fail]$End SSH PermitEmptyPasswords is not set to No."
fi
echo ' '
echo '############################################'
echo ' '
echo '############################################'
echo -e "###### $Blue System Integrity and Intrusion Detection$End ######"
echo '############################################'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 46. Enable SELINUX. $End"
echo ' '
# Check SELinux status
sestatus=$(sestatus | awk '/SELinux status:/ {print $3}')

if [ "$sestatus" == "enabled" ]; then
    echo "$Green[Pass]$End SELinux is enabled."
else
    echo "$Red[Fail]$End SELinux is not enabled."
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 47. Check Globally accessible files and directories. $End"
echo ' '
# Find globally accessible files and folders and save output to file
find / -type f -perm /o+rwx -o -type d -perm /o+rwx > globally_access_file_folder.txt 2>&1
echo 'Globally accessible files and directories List stored at the same location with name:globally_access_file_folder.txt'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 48. Enabling encryption. $End"
echo ' '
# Enable encryption
echo "Checking encryption settings..."
if [ "$(grep -c "^Ciphers.*-cbc" /etc/ssh/sshd_config)" -eq "0" ]; then
    echo "$Red[Fail]$End SSH ciphers is Disabled"
else
    echo "$Green[Pass]$End SSH ciphers is Enabled"
fi
if [ "$(grep -c "^Protocol .*1" /etc/ssh/sshd_config)" -ne "0" ]; then
    echo "$Red[Fail]$End SSH protocol set to 1"
fi
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 49. Checking Open Port. $End"
echo ' '
echo -e "#$Red NMAP is required for this test(You can Install it using: yum install nmap or apt-get install nmap) $End"
echo ' '
# Define variables
PORT_RANGE="1-65535"
OUTPUT_FILE="open_ports.txt"
# Run nmap to check for open ports and save output to a file
nmap -p $PORT_RANGE localhost | grep "open" | awk '{print $1}' > $OUTPUT_FILE
# Count the number of open ports and print to console
OPEN_PORT_COUNT=$(cat $OUTPUT_FILE | wc -l)
echo "There are $OPEN_PORT_COUNT open ports on this system. List can be found on same Location with file name:open_ports.txt"
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 50. Checking running services. $End"
echo ' '
systemctl list-units --type=service --state=running > running_services.txt
echo 'Running Services List stored at the same location with name:running_services.txt'
echo ' '
echo '############################################'
echo ' '
echo -e "#$Yellow 51. Critical Files integrity testing. $End"
echo ' '
# Define array of critical files
CRITICAL_FILES=(
    "/etc/passwd"
	"/etc/shadow"
	"/etc/group"
	"/etc/fstab"
	"/etc/sudoers"
	"/etc/crontab"
	"/etc/sysctl.conf"
	"/etc/hosts"
	"/etc/hostname"
	"/etc/resolv.conf"
    # Add additional critical files here
)
# Loop through critical files and check modification time
for FILE in "${CRITICAL_FILES[@]}"
do
    if [ -f "$FILE" ]; then
        MOD_TIME=$(stat -c %y "$FILE")
        echo "File: $FILE was last modified at $MOD_TIME"
    else
        echo "File: $FILE does not exist"
    fi
done
echo ' '
echo '############################################'
echo ' '
echo 'End of Linux Audit'
echo 'For Explaination of each point, please check Audit-explain.txt file'
echo 'For Solutions to Pass the audit, please check Audit-Solution.txt file' 
echo ' '
echo '############################################'
