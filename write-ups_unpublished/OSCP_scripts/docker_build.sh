#!/bin/bash -u
# Eliot Roxbergh 2024
#
# When compiling .c exploits for old OSes we will get error such as:
#   /path/to/libc.so.6: version 'GLIBC_2.34' not found
# Thus we need to compile it from the correct OS version, as below.
# If still weird, can also check glibc version by running:
#   /lib/x86_64-linux-gnu/libc.so.6 #(path to libc)
#   OR
#   ldd --version ldd
# Here is a similar method but didnt quite work for this lab: https://github.com/X0RW3LL/XenSpawn


echo 'NOTE: use similar or the same OS version
For ubuntu check debian version to use (or use Ubuntu I guess):
    cat /etc/debian_version
'

# NOTE LOOK HERE:
# Discord also hinted of just using gcc older version directly
#docker pull gcc:4.9
#
# For reference they also did:
#       `docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:4.9 gcc -o exploit exploit.c`
#       `file exploit`
#
# But just use this here:
#os="gcc"
#version="4.9"

# NOTE: Debian should work usually for lab machines (they are debian or ubuntu)
# SET OS and VERSION HERE, e.g.
os="ubuntu"
version="20.04"
#os="debian"
#version="10"
#version="bullseye" # equivalent with 11

echo "NOTE! Using $os : $version"
sleep 2
echo; echo
sudo docker pull $os:$version
mkdir ~/docker_shared 2> /dev/null

echo; echo
echo '
#### STEPS ####
# On docker #
apt update && apt install gcc-multilib build-essential -y

# On kali VM: #
# (Copy exploit or whatever to build)
searchsploit -m 41154
mv 41154.sh ~/docker_shared

# On docker image:
cd media
chmod +x 41154.sh
bash 41154.sh
###############
'

echo 'Connecting to Docker instance'
sudo docker run --name $os$version -v ~/docker_shared:/media -it $os:$version /bin/bash

echo 'DONE, can now remove container'; echo

# Extras
# docker ps
# docker exec -it ef041e207540 bash
# docker rm --force ef041e207540
