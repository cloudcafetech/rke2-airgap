#!/usr/bin/env bash
# Inspired from https://ostechnix.com/download-packages-dependencies-locally-ubuntu/
#
# Can be typically run in docker to select the version you want like:
# docker run -it -e K8S_VER=1.26.0-00 -v $(pwd):/host ubuntu:20.04 bash -c "$(cat ./this_script.sh)"

PACKAGES=("docker-ce" "kubectl" "kubelet" "kubernetes-cni" "kubeadm" "apt-transport-https" "ca-certificates" "curl" "openssl" "libapparmor1" "libc6" "perl" "liberror-perl" "git-man" "less" "libbsde" "selinux-utils" "containerd.io" "docker-ce-cli" "cri-tools" "socat" "ebtables" "conntrack" gpg nfs-common nfs-kernel-server curl wget git net-tools unzip jq zip nmap telnet dos2unix apparmor ldap-utils ) 

#K8S_VER=1.26.0-00
K8S_VER_MJ=$(echo "$K8S_VER" | cut -c 1-4)
TZ=Asia/Kolkata
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

apt update; apt install -y apt-rdepends lsb-release
apt install apt-transport-https ca-certificates gpg nfs-common curl wget git net-tools unzip jq zip nmap telnet dos2unix apparmor software-properties-common -y

mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v${K8S_VER_MJ}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v$K8S_VER_MJ/deb/ / | tee /etc/apt/sources.list.d/kubernetes.list

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y
apt install -y containerd.io kubelet kubeadm kubectl

cd /tmp
# Download all dependencies + the package itself
for PACKAGE in ${PACKAGES[@]}; do  apt-get -y -o Dir::Cache::Archives=./ install --download-only --reinstall $PACKAGE; done
# Get them back to the host
cp /tmp/*.deb /host/
