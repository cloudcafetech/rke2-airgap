#!/usr/bin/env bash
OS=xUbuntu_20.04
VERSION=1.26
K8S=1.26.3

systemctl disable containerd --now
systemctl disable docker --now
systemctl stop docker 
systemctl stop containerd
rm -rf /etc/crictl.yaml
apt purge containernetworking-plugins -y
rm -rf /opt/cni/bin/*

sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
swapoff -a

apt update && apt install -y apt-transport-https ca-certificates curl

mkdir -p  /etc/apt/keyrings
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list

curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | gpg --dearmor -o /etc/apt/keyrings/libcontainers-archive-keyring.gpg
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/Release.key | gpg --dearmor -o /etc/apt/keyrings/libcontainers-crio-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/libcontainers-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /" | tee /etc/apt/sources.list.d/devel-kubic-libcontainers-stable.list
echo "deb [signed-by=/etc/apt/keyrings/libcontainers-crio-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /" | tee /etc/apt/sources.list.d/devel-kubic-libcontainers-stable-crio-$VERSION.list

apt update && apt install -y kubelet="$K8S"-00 kubeadm="$K8S"-00 kubectl="$K8S"-00

apt-mark hold kubelet kubeadm kubectl

cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# sysctl params required by setup, params persist across reboots
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# Apply sysctl params without reboot
sudo sysctl --system

# Verify the modules are loaded with the following commands
lsmod | grep br_netfilter
lsmod | grep overlay

# Check the below-mentioned variables are set to 1 for letting iptables seeing bridged traffic
sysctl net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.ipv4.ip_forward

# Install CRIO
apt update && apt install cri-o cri-o-runc cri-tools -y
systemctl enable crio.service --now
echo "runtime-endpoint: unix:///run/crio/crio.sock" > /etc/crictl.yaml

# Set Cluster With Kubeadm
kubeadm config images pull --kubernetes-version v"$K8S"
kubeadm config images list
kubeadm init --kubernetes-version v"$K8S" --ignore-preflight-errors=all

# setup Kube env
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
export KUBECONFIG=/etc/kubernetes/admin.conf
sleep 10
kubectl get node
kubectl get pod -A
export KUBECONFIG=$HOME/.kube/config >> $HOME/.profile

# Install podman
apt install podman -y
