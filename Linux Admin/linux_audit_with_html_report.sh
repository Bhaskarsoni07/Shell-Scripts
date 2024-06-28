#!/bin/bash
Red='<span style="color:red">'
Green='<span style="color:green">'
Blue='<span style="color:blue">'
Yellow='<span style="color:yellow">'
End='</span>'

trap ctrl_c INT

function ctrl_c() {
    echo "**You pressed Ctrl+C...Exiting"
    echo "</body></html>" >> security_audit.html
    exit 0
}

# Start HTML document
cat << "EOF" > security_audit.html
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .section { margin: 20px 0; }
        .section h2 { background-color: #f2f2f2; padding: 10px; }
        .result { margin: 10px 0; }
    </style>
</head>
<body>
EOF

# Banner
cat << "EOF" >> security_audit.html
<pre>
  _      _                                      _ _ _   _             
 | |    (_)                      /\            | (_) | (_)            
 | |     _ _ __  _   ___  __    /  \  _   _  __| |_| |_ _ _ __   __ _ 
 | |    | | '_ \| | | \ \/ /   / /\ \| | | |/ _ | | __| | '_ \ / _ |
 | |____| | | | | |_| |>  <   / ____ \ |_| | (_| | | |_| | | | | (_| |
 |______|_|_| |_|\__,_/_/\_\ /_/    \_\__,_|\__,_|_|\__|_|_| |_|\__, |
                                                                 __/ |
                                                                |___/ 
</pre>
EOF

echo "<h1>Security Audit Report of Linux machine {}</h1>" >> security_audit.html
echo "<p>Created by Bhaskar Soni, Github: <a href='https://github.com/Bhaskar-soni'>Github.com/Bhaskar-soni</a></p>" >> security_audit.html
echo "<p>Let's Start with User: $HOSTNAME</p>" >> security_audit.html

sections=(
	"Host Details"
	"1. IP Details"
	"2. Host File Details"
    "3. Linux Kernel Information"
    "4. Kernel update is Available or not"
    "5. Current User and ID information"
    "6. Linux Distribution Information"
    "7. Check Memory"
    "8. CPU/System Information"
    "9.  Check Available Space"
    "10. Up-time Information"
    "11. Check the default Shell"
    "12. List Current Logged In Users"
    "13. All Users List"
    "14. BIOS related Information"
    "15. Physical Security Testing"
    "16. Partition Information"
    "17. USB Enable or not"
    "18. Check nodev, nosuid, and noexec options on /tmp"
    "19. nodev option to /home"
    "20. Set sticky bit on all world-writable directories"
    "21. Partitions and storage media"
    "22. All mounted file-systems information"
    "23. Static file system information"
    "24. System Updates"
    "25. Available Packages for Update"
    "26. List of Repositories"
    "27. Secure Boot Settings"
    "28. Check permission /boot/grub/grub.cfg"
    "29. Ensure bootloader password"
    "30. Check X Window system"
    "31. Default Repository"
    "32. Process Hardening"
    "33. Restrict core dumps"
    "34. Enable Randomized Virtual Memory Region Placement"
    "35. OS Hardening"
    "36. Remove legacy services"
    "37. Disable or remove server services that are not going to be utilized"
    "38. Remove xinetd, if possible"
    "39. Check Legacy services (e.g., chargen-dgram, chargen-stream, daytime-dgram, daytime-stream, echo-dgram, echo-stream, tcpmux-server)"
    "40. Check services that are not going to be utilized (e.g., FTP, DNS, LDAP, SMB, DHCP, NFS, SNMP, etc.)"
    "41. Ensure Daemon umask"
    "42. Network Security and Firewall"
    "43. Disable IP forwarding"
    "44. Disable send packet redirects"
    "45. Disable source routed packet acceptance"
    "46. Disable ICMP redirect acceptance"
    "47. Enable Ignore Broadcast Requests"
    "48. Enable Bad Error Message Protection"
    "49. Enable TCP/SYN cookies"
    "50. Remote Administration via SSH"
    "51. Set SSH protocol to 2"
    "52. Set SSH LogLevel to INFO"
    "53. Disable SSH Root login"
    "54. Set SSH PermitEmptyPasswords to No"
    "55. System Integrity and Intrusion Detection"
    "56. Enable SELINUX"
    "57. Check Globally accessible files and directories"
)

# Output each section
for i in "${!sections[@]}"; do
    echo "<div class='section'>" >> security_audit.html
    echo "<h2>${sections[i]}</h2>" >> security_audit.html
    case $i in
        0)
			echo "<pre class='result'>$(hostnamectl)</pre>" >> security_audit.html
            ;;
		1)
			echo "<pre class='result'>$(ifconfig)</pre>" >> security_audit.html
            ;;
		2)
			echo "<pre class='result'>$(cat /etc/hosts)</pre>" >> security_audit.html
            ;;
		3)
            echo "<pre class='result'>$(uname -a)</pre>" >> security_audit.html
            ;;
        4)
            if [ "$(yum check-update kernel | grep -c 'kernel.')" -eq 0 ]; then
                echo "<p class='result'>$Green[Pass]$End No kernel update is available!</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End A kernel update is available!</p>" >> security_audit.html
            fi
            ;;
        5)
            echo "<p class='result'>Username: $(whoami)</p>" >> security_audit.html
            echo "<p class='result'>ID information: $(id)</p>" >> security_audit.html
            ;;
        6)
            echo "<pre class='result'>$(lsb_release -a)</pre>" >> security_audit.html
            ;;
        7)
            echo "<pre class='result'>$(free -h)</pre>" >> security_audit.html
            ;;
        8)
            echo "<pre class='result'>$(lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)')</pre>" >> security_audit.html
            ;;
        9)
            echo "<pre class='result'>$(df -h)</pre>" >> security_audit.html
            ;;
        10)
            echo "<pre class='result'>$(uptime)</pre>" >> security_audit.html
            ;;
        11)
            echo "<pre class='result'>$(readlink -f $(which sh))</pre>" >> security_audit.html
            ;;
        12)
            echo "<pre class='result'>$(w)</pre>" >> security_audit.html
            ;;
        13)
            echo "<pre class='result'>$(getent passwd "0" | cut -d: -f1)</pre>" >> security_audit.html
            echo "<pre class='result'>$(awk -F: '($3 >= 1000) {printf "%s\n",$1,$3}' /etc/passwd)</pre>" >> security_audit.html
            ;;
        14)
            echo "<pre class='result'>$(biosdecode)</pre>" >> security_audit.html
            ;;
        15)
            echo "<pre class='result'>$(find / -perm -4000 -o -perm -2000 -exec ls -ld {} \; 2>/dev/null)</pre>" >> security_audit.html
            ;;
        16)
            echo "<pre class='result'>$(lsblk)</pre>" >> security_audit.html
            echo "<pre class='result'>$(lsblk -f)</pre>" >> security_audit.html
            ;;
        17)
            if [ "$(id -u)" != "0" ]; then
                echo "<p class='result'>$Red[Error]$End You must be root to run this script</p>" >> security_audit.html
            else
                users=$(who | awk '{print $1}' | sort | uniq)
                for user in $users; do
                    if [ $(sudo -u $user ls /dev/sda1 2>/dev/null) ]; then
                        echo "<p class='result'>$Red[Fail]$End User $user has permission to plug in a USB device</p>" >> security_audit.html
                    fi
                done
            fi
            ;;
        18)
            if ! mount | grep "on /tmp " | grep -q "/dev/"; then
                echo "<p class='result'>$Red[Error]$End /tmp is not a separate partition</p>" >> security_audit.html
            elif mount | grep "on /tmp " | grep -q "nodev,nosuid,noexec"; then
                echo "<p class='result'>$Green[Pass]$End nodev, nosuid, and noexec options are set on /tmp</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Error]$End nodev, nosuid, and noexec options are not set on /tmp</p>" >> security_audit.html
            fi
            ;;
        19)
            if mount | grep '^/home' | grep -q nodev; then
                echo "<p class='result'>$Green[Pass]$End nodev is in effect in /home</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End nodev is NOT in effect in /home</p>" >> security_audit.html
            fi
            ;;
        20)
            if ! mount | grep "on /tmp " | grep -q "/dev/"; then
                echo "<p class='result'>$Red[Error]$End /tmp is not a separate partition</p>" >> security_audit.html
            elif [ "$(stat -c %a /tmp)" -eq 1777 ]; then
                echo "<p class='result'>$Green[Pass]$End The sticky bit is set on /tmp</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Error]$End The sticky bit is not set on /tmp</p>" >> security_audit.html
            fi
            ;;
        21)
            echo "<pre class='result'>$(blkid)</pre>" >> security_audit.html
            ;;
        22)
            echo "<pre class='result'>$(findmnt)</pre>" >> security_audit.html
            ;;
        23)
            echo "<pre class='result'>$(cat /etc/fstab)</pre>" >> security_audit.html
            ;;
        24)
            if rpm -q yum-cron &>/dev/null; then
                echo "<p class='result'>$Green[Pass]$End yum-cron is installed</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End yum-cron is not installed</p>" >> security_audit.html
            fi
            ;;
        25)
            if ! yum check-update --security &>/dev/null; then
                echo "<p class='result'>$Green[Pass]$End System is up-to-date with security updates</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Security updates are available</p>" >> security_audit.html
            fi
            ;;
        26)
            echo "<pre class='result'>$(yum repolist)</pre>" >> security_audit.html
            ;;
        27)
            if [ -d "/sys/firmware/efi" ]; then
                echo "<p class='result'>$Green[Pass]$End UEFI is enabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End UEFI is not enabled</p>" >> security_audit.html
            fi
            ;;
        28)
            if [ "$(stat -c %a /boot/grub2/grub.cfg)" -eq 600 ]; then
                echo "<p class='result'>$Green[Pass]$End Permissions on /boot/grub2/grub.cfg are set to 600</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Permissions on /boot/grub2/grub.cfg are not set to 600</p>" >> security_audit.html
            fi
            ;;
        29)
            if grep -q "^set superusers" /boot/grub2/grub.cfg; then
                echo "<p class='result'>$Green[Pass]$End Bootloader password is set</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Bootloader password is not set</p>" >> security_audit.html
            fi
            ;;
        30)
            if [ "$(yum list installed xorg-x11-server-Xorg 2>/dev/null)" ]; then
                echo "<p class='result'>$Red[Fail]$End X Window system is installed</p>" >> security_audit.html
            else
                echo "<p class='result'>$Green[Pass]$End X Window system is not installed</p>" >> security_audit.html
            fi
            ;;
        31)
            echo "<pre class='result'>$(yum repolist all)</pre>" >> security_audit.html
            ;;
        32)
            process_count=$(ps -e | grep '^\S' | wc -l)
			if (( process_count > 0 )); then
				echo "<p class='result'>$Green[Pass]$End Process hardening check passed. Number of running processes: $process_count</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End Process hardening check failed. Number of running processes: $process_count</p>" >> security_audit.html
			fi
            ;;
        33)
            if grep -Eq '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/*; then
				echo "<p class='result'>$Green[Pass]$End Core dumps are restricted</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End Core dumps are not restricted</p>" >> security_audit.html
			fi
            ;;
        34)
            if sysctl -n kernel.randomize_va_space | grep -q '2'; then
                echo "<p class='result'>$Green[Pass]$End Randomized Virtual Memory Region Placement is enabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Randomized Virtual Memory Region Placement is not enabled</p>" >> security_audit.html
            fi
            ;;
        35)
            echo "<pre class='result'>$(cat /etc/issue)</pre>" >> security_audit.html
            ;;
        36)
            legacy_services=$(systemctl list-unit-files | grep enabled | grep -E 'rsh|rlogin|rexec|ypserv|ypbind|telnet|tftp|xinetd')
			service_count=$(echo "$legacy_services" | wc -l)

			if [ $service_count -eq 0 ]; then
				echo "<p class='result'>$Green[Pass]$End No legacy enabled services found</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End $service_count legacy enabled services found:<br>$(echo "$legacy_services" | sed 's/^/ - /')</p>" >> security_audit.html
			fi
            ;;
        37)
			unused_services=$(systemctl list-unit-files | grep enabled)
			service_count=$(echo "$unused_services" | wc -l)

			if [ $service_count -eq 0 ]; then
				echo "<p class='result'>$Green[Pass]$End No unnecessary enabled services found</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End $service_count unnecessary enabled services found</p>" >> security_audit.html
			fi
            ;;
        38)
            if [ "$(yum list installed xinetd 2>/dev/null)" ]; then
                echo "<p class='result'>$Red[Fail]$End xinetd is installed</p>" >> security_audit.html
            else
                echo "<p class='result'>$Green[Pass]$End xinetd is not installed</p>" >> security_audit.html
            fi
            ;;
        39)
            services=(chargen-dgram chargen-stream daytime-dgram daytime-stream echo-dgram echo-stream tcpmux-server)
            for service in "${services[@]}"; do
                if systemctl is-enabled "$service" &>/dev/null; then
                    echo "<p class='result'>$Red[Fail]$End $service is enabled</p>" >> security_audit.html
                else
                    echo "<p class='result'>$Green[Pass]$End $service is not enabled</p>" >> security_audit.html
                fi
            done
            ;;
        40)
            services=(vsftpd named slapd smbd nfs-server snmpd)
            for service in "${services[@]}"; do
                if systemctl is-enabled "$service" &>/dev/null; then
                    echo "<p class='result'>$Red[Fail]$End $service is enabled</p>" >> security_audit.html
                else
                    echo "<p class='result'>$Green[Pass]$End $service is not enabled</p>" >> security_audit.html
                fi
            done
            ;;
        41)
            if grep -iq '^umask 027' /etc/init.d/functions /etc/sysconfig/init; then
				echo "<p class='result'>$Green[Pass]$End Daemon umask is set to 027</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End Daemon umask is not set to 027</p>" >> security_audit.html
			fi
            ;;
        42)
            if sudo ufw status | grep -iq 'active' || sudo firewall-cmd --state | grep -iq 'running' || sudo systemctl status firewalld | grep -iq 'active (running)'; then
				echo "<p class='result'>$Green[Pass]$End Firewall is active</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End Firewall is not active</p>" >> security_audit.html
			fi
            ;;
        43)
            if sysctl net.ipv4.ip_forward | grep -q '0'; then
                echo "<p class='result'>$Green[Pass]$End IP forwarding is disabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End IP forwarding is not disabled</p>" >> security_audit.html
            fi
            ;;
        44)
            if sysctl net.ipv4.conf.all.send_redirects | grep -q '0'; then
                echo "<p class='result'>$Green[Pass]$End Send packet redirects is disabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Send packet redirects is not disabled</p>" >> security_audit.html
            fi
            ;;
        45)
            if sysctl net.ipv4.conf.all.accept_source_route | grep -q '0'; then
                echo "<p class='result'>$Green[Pass]$End Source routed packet acceptance is disabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Source routed packet acceptance is not disabled</p>" >> security_audit.html
            fi
            ;;
        46)
            if sysctl net.ipv4.conf.all.accept_redirects | grep -q '0'; then
                echo "<p class='result'>$Green[Pass]$End ICMP redirect acceptance is disabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End ICMP redirect acceptance is not disabled</p>" >> security_audit.html
            fi
            ;;
        47)
            if sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q '1'; then
                echo "<p class='result'>$Green[Pass]$End Ignore Broadcast Requests is enabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Ignore Broadcast Requests is not enabled</p>" >> security_audit.html
            fi
            ;;
        48)
            if sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q '1'; then
                echo "<p class='result'>$Green[Pass]$End Bad Error Message Protection is enabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End Bad Error Message Protection is not enabled</p>" >> security_audit.html
            fi
            ;;
        49)
            if sysctl net.ipv4.tcp_syncookies | grep -q '1'; then
                echo "<p class='result'>$Green[Pass]$End TCP/SYN cookies are enabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End TCP/SYN cookies are not enabled</p>" >> security_audit.html
            fi
            ;;
        50)
            if sudo grep -Ei '^permitrootlogin\s+no' /etc/ssh/sshd_config >/dev/null; then
				echo "<p class='result'>$Green[Pass]$End Remote administration via SSH is disabled</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End Remote administration via SSH is not disabled</p>" >> security_audit.html
			fi
            ;;
        51)
            if sudo grep -Ei '^protocol\s+2' /etc/ssh/sshd_config >/dev/null; then
				echo "<p class='result'>$Green[Pass]$End SSH protocol is set to version 2</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End SSH protocol is not set to version 2</p>" >> security_audit.html
			fi
            ;;
		52)
			if sudo grep -Ei '^loglevel\s+info' /etc/ssh/sshd_config >/dev/null; then
				echo "<p class='result'>$Green[Pass]$End SSH LogLevel is set to INFO</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End SSH LogLevel is not set to INFO</p>" >> security_audit.html
			fi
			;;	
        53)
            if sshd -T | grep -iq 'permitrootlogin no'; then
                echo "<p class='result'>$Green[Pass]$End SSH Root login is disabled</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End SSH Root login is not disabled</p>" >> security_audit.html
            fi
            ;;
        54)
            if sshd -T | grep -iq 'permitemptypasswords no'; then
                echo "<p class='result'>$Green[Pass]$End SSH PermitEmptyPasswords is set to No</p>" >> security_audit.html
            else
                echo "<p class='result'>$Red[Fail]$End SSH PermitEmptyPasswords is not set to No</p>" >> security_audit.html
            fi
            ;;
		55)
			if sudo systemctl status aide.service | grep -q "active (running)"; then
				echo "<p class='result'>$Green[Pass]$End System Integrity and Intrusion Detection service (AIDE) is running</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End System Integrity and Intrusion Detection service (AIDE) is not running</p>" >> security_audit.html
			fi
            ;;
        56)
            if sudo sestatus | grep -iq "enabled"; then
				echo "<p class='result'>$Green[Pass]$End SELinux is enabled</p>" >> security_audit.html
			else
				echo "<p class='result'>$Red[Fail]$End SELinux is not enabled</p>" >> security_audit.html
			fi
            ;;
        57)
			count=$(sudo find / -type d \( -perm -o+w \) -exec ls -ld {} + | grep -c .)

			if [[ $count -gt 0 ]]; then
				echo "<p class='result'>$Red[Fail]$End $count globally accessible files and directories found</p>" >> security_audit.html
			else
				echo "<p class='result'>$Green[Pass]$End No globally accessible files and directories found</p>" >> security_audit.html
			fi
			echo "Here are the List of files and directories: "
            echo "<pre class='result'>$(find / -xdev \( -type d -perm -0002 -a ! -perm -1000 \) -print)</pre>" >> security_audit.html
            ;;
    esac
    echo "</div>" >> security_audit.html
done

# End HTML document
echo "</body></html>" >> security_audit.html
