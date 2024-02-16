#!/bin/bash

K8SV=1.28.3
K8SM=$(echo $K8SV | cut -c 1-4)

images=(
    registry.k8s.io/kube-apiserver:v"$K8SV"
    registry.k8s.io/kube-controller-manager:v"$K8SV"
    registry.k8s.io/kube-scheduler:v"$K8SV"
    registry.k8s.io/kube-proxy:v"$K8SV"
    "registry.k8s.io/pause:3.9"
    "registry.k8s.io/etcd:3.5.10-0"
    "registry.k8s.io/coredns/coredns:v1.10.1"  
)

  mkdir /root/kubeadm_"$K8SV"
  cd /root/kubeadm_"$K8SV"
  for image in "${images[@]}"; do
    docker pull "$image"
    image_name=$(echo "$image" | sed 's|/|_|g' | sed 's/:/_/g')
    docker save -o "${image_name}.tar" "$image"
  done

docker rmi $(docker images | grep -v TAG | awk '{ print $3 }')

sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
swapoff -a

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

mkdir /root/pkg
cd /root/pkg
curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/ubuntu-kubeadm-pkg.sh && chmod 755 ubuntu-kubeadm-pkg.sh
docker run -it -e K8S=$K8SM -v $(pwd):/host ubuntu:20.04 bash -c "$(cat ./ubuntu-kubeadm-pkg.sh)"

sleep 10
systemctl disable containerd --now
systemctl stop containerd
systemctl disable docker --now
systemctl stop docker 
rm -rf /etc/crictl.yaml
apt purge containernetworking-plugins -y
rm -rf /opt/cni/bin/*

dpkg -i *.deb
sleep 10

systemctl enable crio --now
echo "runtime-endpoint: unix:///run/crio/crio.sock" > /etc/crictl.yaml

   cd /root/kubeadm_"$K8SV"
   for image in "${images[@]}"; do
    tarfile=`echo "$image" | sed -e "s:/:_:g" | sed -e "s/:/_/g"`
    if [[ -f "$tarfile.tar" ]]; then
      podman load -i "$tarfile".tar
    else
      echo "File "$tarfile".tar not found!" 1>&2
    fi
   done

# Set Cluster With Kubeadm
#kubeadm config images pull --kubernetes-version v"$K8SV"
#kubeadm config images list
kubeadm init --kubernetes-version v"$K8SV" --ignore-preflight-errors=all

# setup Kube env
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
export KUBECONFIG=/etc/kubernetes/admin.conf
sleep 10
kubectl get node
kubectl get pod -A
export KUBECONFIG=$HOME/.kube/config >> $HOME/.profile
