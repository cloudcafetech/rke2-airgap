#!/bin/bash
wget http://10.182.15.216:8080/ubuntu-repo/nfs-common_1.3.4-2.5ubuntu3_amd64.deb
wget http://10.182.15.216:8080/ubuntu-repo/libnfsidmap2_0.25-5.1ubuntu1_amd64.deb
wget http://10.182.15.216:8080/ubuntu-repo/libtirpc3_1.2.5-1_amd64.deb
wget http://10.182.15.216:8080/ubuntu-repo/rpcbind_1.2.5-8_amd64.deb
wget http://10.182.15.216:8080/ubuntu-repo/keyutils_1.6-6ubuntu1_amd64.deb
wget http://10.182.15.216:8080/ubuntu-repo/libtirpc-common_1.2.5-1_all.deb

# Transfer the debs to the target machine and installed them with this order
dpkg -i libnfsidmap2_0.25-5.1ubuntu1_amd64.deb && \
dpkg -i libtirpc-common_1.2.5-1_all.deb && \
dpkg -i libtirpc3_1.2.5-1_amd64.deb && \
dpkg -i rpcbind_1.2.5-8_amd64.deb && \
dpkg -i keyutils_1.6-6ubuntu1_amd64.deb && \
dpkg -i nfs-common_1.3.4-2.5ubuntu3_amd64.deb
