#!/usr/bin/env bash
# Inspired from https://ostechnix.com/download-packages-dependencies-locally-ubuntu/
#
# Can be typically run in docker to select the version you want like:
# docker run -it -v $(pwd):/host ubuntu:20.04 bash -c "$(cat ./this_script.sh)"

PACKAGES="apt-transport-https ca-certificates gpg nfs-common nfs-kernel-server curl wget git net-tools unzip jq zip nmap telnet dos2unix apparmor ldap-utils"
apt update; apt install -y apt-rdepends lsb-release
cd /tmp
# Download all dependencies + the package itself
for pkg in $PACKAGES;
do
 apt-get download $(apt-rdepends ${pkg} | grep -v "^ " | sed 's/debconf-2.0/debconf/g')
done
# Get them back to the host
cp /tmp/*.deb /host/
