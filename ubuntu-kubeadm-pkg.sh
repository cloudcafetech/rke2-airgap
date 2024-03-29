#!/usr/bin/env bash
# Inspired from https://ostechnix.com/download-packages-dependencies-locally-ubuntu/
#
# Can be typically run in docker to select the version you want like:
# docker run -it -e K8S=1.26 -v $(pwd):/host ubuntu:20.04 bash -c "$(cat ./this_script.sh)"

# For crio
PKGCRIOS=(kubectl kubelet kubernetes-cni kubeadm apt-transport-https ca-certificates curl openssl selinux-utils cri-o cri-o-runc podman cri-tools socat ebtables conntrack gpg nmap) 
# For containerd 
PKGCONDS=(kubectl kubelet kubernetes-cni kubeadm apt-transport-https ca-certificates curl openssl libapparmor1 libc6 perl liberror-perl git-man less selinux-utils containerd.io docker-ce docker-ce-cli cri-tools socat ebtables conntrack gpg nmap) 

OS=xUbuntu_20.04
VERSION=1.26
#K8S=1.26

TZ=Asia/Kolkata
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

apt update; apt install -y apt-rdepends lsb-release
apt install apt-transport-https ca-certificates gpg curl wget git software-properties-common -y

mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v${K8S}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v$K8S/deb/ / | tee /etc/apt/sources.list.d/kubernetes.list

# For crio
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | gpg --dearmor -o /etc/apt/keyrings/libcontainers-archive-keyring.gpg
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/Release.key | gpg --dearmor -o /etc/apt/keyrings/libcontainers-crio-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/libcontainers-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /" | tee /etc/apt/sources.list.d/devel-kubic-libcontainers-stable.list
echo "deb [signed-by=/etc/apt/keyrings/libcontainers-crio-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /" | tee /etc/apt/sources.list.d/devel-kubic-libcontainers-stable-crio-$VERSION.list

# For containerd 
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y

apt update

cd /tmp
mkdir crio cond
# Download all dependencies CONTAINERD package 
cd /tmp/cond
for PKGCOND in ${PKGCONDS[@]}; do  apt-get -y -o Dir::Cache::Archives=./ install --download-only --reinstall $PKGCOND; done
rm -rf containernetworking-plugins*.deb

# Download all dependencies CRIO package 
cd /tmp/crio
for PKGCRIO in ${PKGCRIOS[@]}; do  apt-get -y -o Dir::Cache::Archives=./ install --download-only --reinstall $PKGCRIO; done
rm -rf containernetworking-plugins*.deb

# Get them back to the host
cp -rf /tmp/c* /host/
