#!/bin/bash
# Note, we are using "echo 3", but it is not recommended in production instead use "echo 1"
echo "echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a && printf '\n%s\n' 'Ram-cache and Swap Cleared'" >> clearcache.sh

##Assign the permission to the file
chmod 755 clearcache.sh

##Create an entry in crontab file using following command.
crontab -e
#0  2  *  *  *  /path/to/clearcache.sh
