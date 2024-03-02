#!/bin/bash

# mkdir /opt/k8s && cd /opt/k8s && curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/k8sag.sh && chmod 755 k8sag.sh

# interesting https://kubernetes.io/blog/2023/10/12/bootstrap-an-air-gapped-cluster-with-kubeadm/

#set -ebpf

#K8SCNI=CRIO

BUILD_SERVER_PUBIP=`curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//'`
BUILD_SERVER_IP=`ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1`
BUILD_SERVER_DNS=`hostname`
LB_IP=

TOKEN=tun848.2hlz8uo37jgy5zqt

MASTERDNS1=master1
MASTERDNS2=master2
MASTERDNS3=master3

MASTERIP1=
MASTERIP2=
MASTERIP3=

INFRAIP1=
INFRAIP2=

INFRADNS1=
INFRANDS2=

# versions
UARCH=$(uname -m)
if [[ "$UARCH" == "arm64" || "$UARCH" == "aarch64" ]]; then
    ARCH="aarch64"
    K8s_ARCH="arm64"
else
    ARCH="x86_64"
    K8s_ARCH="amd64"
fi

CNI_PLUGINS_VERSION="v1.3.0"
CRICTL_VERSION="v1.27.0"
KUBE_RELEASE="v1.28.6"
K8S_VER=1.28.6-00
K8S_VER_MJ=$(echo "$K8S_VER" | cut -c 1-4)
RELEASE_VERSION="v0.15.1"
K9S_VERSION="v0.27.4"
CERT_VERSION=v1.13.3
RANCHER_VERSION=2.8.1
LONGHORN_VERSION=1.5.3
NEU_VERSION=2.6.6
DOMAIN="$LB_IP".nip.io

images=(
    "registry.k8s.io/kube-apiserver:${KUBE_RELEASE}"
    "registry.k8s.io/kube-controller-manager:${KUBE_RELEASE}"
    "registry.k8s.io/kube-scheduler:${KUBE_RELEASE}"
    "registry.k8s.io/kube-proxy:${KUBE_RELEASE}"
    "registry.k8s.io/pause:3.6"
    "registry.k8s.io/pause:3.8"
    "registry.k8s.io/pause:3.9"
    "registry.k8s.io/etcd:3.5.10-0"
    "registry.k8s.io/etcd:3.5.9-0"
    "registry.k8s.io/coredns/coredns:v1.10.1" 
)

######  NO MOAR EDITS #######
export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'

export PATH=$PATH:/usr/local/bin

########################## Certificate Generate ###########################
certgen() {

cat <<EOF > san.cnf
[req]
default_bits  = 2048
distinguished_name = req_distinguished_name
req_extensions = req_ext
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
countryName = IN
stateOrProvinceName = WB
localityName = KOL
organizationName = Cloud Cafe
commonName = 127.0.0.1: Cloud Cafe

[req_ext]
subjectAltName = @alt_names

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $BUILD_SERVER_DNS
DNS.2 = localhost
IP.1 = $BUILD_SERVER_IP
IP.2 = 127.0.0.1
EOF

openssl genrsa 1024 > domain.key
chmod 400 domain.key
openssl req -new -x509 -nodes -sha1 -days 365 -key domain.key -out domain.crt -config san.cnf

}

########################## Webserver Setup ################################
websetup() {

echo - Apache Web Server

if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
 apt install apache2 -y
 sed -i 's/Listen 80/Listen 0.0.0.0:8080/' /etc/apache2/ports.conf
 sed -i 's/80/8080/' /etc/apache2/sites-enabled/000-default.conf
 systemctl start apache2;systemctl enable apache2
 systemctl restart apache2
else
 yum install -y httpd
 sed -i 's/Listen 80/Listen 0.0.0.0:8080/' /etc/httpd/conf/httpd.conf
 setsebool -P httpd_read_user_content 1
 systemctl start httpd;systemctl enable httpd
fi 

# Mount CentOS 8 ISO for CentOS
if [ ! -d /mnt/iso ]; then
 mkdir /mnt/iso
fi

if [[ ! -f /mnt/iso/media.repo ]]; then 
 mount -t iso9660 -o ro,loop CentOS-Stream-8-x86_64-latest-dvd1.iso /mnt/iso
fi 

if [[ ! -f /var/www/html/iso/media.repo ]]; then 
cp -vaR /mnt/iso /var/www/html/

cat <<EOF > /var/www/html/iso/centos8-remote.repo
[centos8_Appstream_remote]
baseurl=http://$BUILD_SERVER_IP:8080/iso/AppStream
gpgcheck=0
name=CentOS Linux App_stream remote
enable=1

[centos8_BaseOS_remote]
baseurl=http://$BUILD_SERVER_IP:8080/iso/BaseOS
gpgcheck=0
name=CentOS Linux BaseOS remote
enable=1
EOF

chcon -R -t httpd_sys_content_t /var/www/html/iso
chown -R apache: /var/www/html/iso/
chmod 755 /var/www/html/iso
umount /mnt/iso
fi

if [[ ! -d /var/www/html/ubuntu-repo ]]; then 
  mkdir -p /var/www/html/ubuntu-repo
  cp -vaR /root/ubuntu-repo /var/www/html/
  chcon -R -t httpd_sys_content_t /var/www/html/ubuntu-repo
  chown -R apache: /var/www/html/ubuntu-repo/
  chmod 755 /var/www/html/ubuntu-repo
fi

cp -vaR /opt/k8s/k8s_"$KUBE_RELEASE" /var/www/html/
cp -vaR /opt/k8s/images/kubeadm_"$KUBE_RELEASE" /var/www/html/
cp /opt/k8s/k8sag.sh /var/www/html/k8s_"$KUBE_RELEASE"/
cp /opt/k8s/images/kubeadm_"$KUBE_RELEASE"/kube-image.tar.gz /var/www/html/k8s_"$KUBE_RELEASE"/
cp /opt/k8s/k8s_$KUBE_RELEASE/registries.conf /var/www/html/k8s_"$KUBE_RELEASE"/
cp /opt/k8s/images/others/kube-flannel.yml /var/www/html/k8s_"$KUBE_RELEASE"/
cp /opt/k8s/images/others/ingress-controller.yaml /var/www/html/k8s_"$KUBE_RELEASE"/
cp /opt/k8s/helm/helm-v3.13.2-linux-amd64.tar.gz /var/www/html/k8s_"$KUBE_RELEASE"/

chcon -R -t httpd_sys_content_t /var/www/html/k8s_"$KUBE_RELEASE"
chown -R apache: /var/www/html/k8s_"$KUBE_RELEASE"/
chmod 755 /var/www/html/k8s_"$KUBE_RELEASE"

chcon -R -t httpd_sys_content_t /var/www/html/kubeadm_"$KUBE_RELEASE"
chown -R apache: /var/www/html/kubeadm_"$KUBE_RELEASE"/
chmod 755 /var/www/html/kubeadm_"$KUBE_RELEASE"

echo "mkdir /opt/k8s && cd /opt/k8s && curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/k8sag.sh  && chmod 755 k8sag.sh"

}

################################# LB Setup ################################
function lbsetup () {

  echo - Configuring HAProxy Server
  #yum install haproxy -y 

  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   apt install -y haproxy  
  else
   yum install -y haproxy 
  fi

cat <<EOF > /etc/haproxy/haproxy.cfg
# Global settings
#---------------------------------------------------------------------
global
    maxconn     20000
    log         /dev/log local0 info
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    user        haproxy
    group       haproxy
    daemon
    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats
#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    log                     global
    mode                    http
    option                  httplog
    option                  dontlognull
    option http-server-close
    option redispatch
    option forwardfor       except 127.0.0.0/8
    retries                 3
    maxconn                 20000
    timeout http-request    10000ms
    timeout http-keep-alive 10000ms
    timeout check           10000ms
    timeout connect         40000ms
    timeout client          300000ms
    timeout server          300000ms
    timeout queue           50000ms

# Enable HAProxy stats
listen stats
    bind :9000
    stats uri /stats
    stats refresh 10000ms

# Kube API Server
frontend k8s_api_frontend
    bind *:6443
    default_backend k8s_api_backend
    mode tcp

backend k8s_api_backend
    mode tcp
    balance roundrobin
    server      $MASTERDNS1 $MASTERIP1:6443 check
    server      $MASTERDNS2 $MASTERIP2:6443 check
    server      $MASTERDNS3 $MASTERIP3:6443 check

# K8S Ingress - layer 4 tcp mode for each. Ingress Controller will handle layer 7.
frontend k8s_http_ingress_frontend
    bind :80
    default_backend k8s_http_ingress_backend
    mode http

backend k8s_http_ingress_backend
    mode http
    balance roundrobin
    server      $MASTERDNS1 $MASTERIP1:80 check
    server      $MASTERDNS2 $MASTERIP2:80 check
    server      $MASTERDNS3 $MASTERIP3:80 check

frontend k8s_https_ingress_frontend
    bind *:443
    default_backend k8s_https_ingress_backend
    mode tcp

backend k8s_https_ingress_backend
    mode tcp
    balance roundrobin
    server      $MASTERDNS1 $MASTERIP1:443 check
    server      $MASTERDNS2 $MASTERIP2:443 check
    server      $MASTERDNS3 $MASTERIP3:443 check
EOF


  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   systemctl start haproxy;systemctl enable haproxy
   echo - Stopping and disabling firewall 
   systemctl stop ufw
   systemctl stop apparmor.service
   systemctl disable --now ufw
   systemctl disable --now apparmor.service 
  else

cat <<EOF > /etc/rsyslog.d/99-haproxy.conf
$AddUnixListenSocket /var/lib/haproxy/dev/log

# Send HAProxy messages to a dedicated logfile
:programname, startswith, "haproxy" {
  /var/log/haproxy.log
  stop
}
EOF
   mkdir /var/lib/haproxy/dev
   setsebool -P haproxy_connect_any 1
   systemctl start haproxy;systemctl enable haproxy;systemctl restart rsyslog;systemctl restart haproxy
   firewall-cmd --add-port=6443/tcp --permanent
   firewall-cmd --add-port=443/tcp --permanent
   firewall-cmd --add-service=http --permanent
   firewall-cmd --add-service=https --permanent
   firewall-cmd --add-port=9000/tcp --permanent
   firewall-cmd --add-port=9345/tcp --permanent
   firewall-cmd --reload 
  fi

}

################################# Image Upload ################################
function imageload () {

  if [[ -z "$BUILD_SERVER_IP" ]]; then 
   echo - Please enter Build Server IP in variable
   exit
  fi

  echo - "Check & Install docker, crane & setup docker Private Registry"
  if ! command -v docker &> /dev/null;
  then
    echo "Trying to Install Docker..."
    if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
      apt update -y && apt install docker.io -y
      systemctl start docker; systemctl enable docker
    else
      curl -s https://releases.rancher.com/install-docker/19.03.sh | sh
      systemctl start docker; systemctl enable docker
    fi
  fi 
  systemctl restart docker

  if ! command -v crane &> /dev/null;
  then
    echo "Trying to Install Crane..."
    curl -sL "https://github.com/google/go-containerregistry/releases/download/v0.19.0/go-containerregistry_Linux_x86_64.tar.gz" > go-containerregistry.tar.gz
    tar -zxvf go-containerregistry.tar.gz -C /usr/local/bin/ crane
  fi 

  mkdir -p /root/registry/data/auth
  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   OS=Ubuntu
  else
   chcon system_u:object_r:container_file_t:s0 /root/registry/data
  fi

  echo - Private Registry Setup
  if ! test -f /root/registry/data/auth/htpasswd; then
    docker run --name htpass --entrypoint htpasswd httpd:2 -Bbn admin admin@2675 > /root/registry/data/auth/htpasswd  
    docker rm htpass
  fi

  PR=`docker ps -a -q -f name=private-registry`
  if [[ $PR == "" ]]; then
    docker run -itd -p 5000:5000 --restart=always --name private-registry \
    -v /root/registry/data/auth:/auth -v /root/registry/data:/var/lib/registry \
    -v /root/registry/data/certs:/certs -v /root/registry/data/certs:/certs \
    -e REGISTRY_AUTH=htpasswd -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
    registry
  fi

  echo - Checking helm 
  if ! command -v helm &> /dev/null;
  then
   echo - Get Helm Charts
   cd /opt/k8s/helm/
   echo - get helm
   curl -#LO https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
   rm -rf linux-amd64 > /dev/null 2>&1
  fi
   
  echo - add repos
  cd /opt/k8s/helm/
  helm repo add jetstack https://charts.jetstack.io --force-update > /dev/null 2>&1
  helm repo add rancher-latest https://releases.rancher.com/server-charts/latest --force-update> /dev/null 2>&1
  helm repo add longhorn https://charts.longhorn.io --force-update> /dev/null 2>&1
  helm repo add neuvector https://neuvector.github.io/neuvector-helm/ --force-update> /dev/null 2>&1

  echo - get charts
  helm pull jetstack/cert-manager --version $CERT_VERSION > /dev/null 2>&1
  helm pull rancher-latest/rancher --version v$RANCHER_VERSION > /dev/null 2>&1
  helm pull longhorn/longhorn --version $LONGHORN_VERSION > /dev/null 2>&1
  helm pull neuvector/core --version $NEU_VERSION > /dev/null 2>&1

  echo - Get Images - Rancher/Longhorn
  mkdir -p /opt/k8s/helm /opt/k8s/images/{cert,rancher,longhorn,registry,flask,neuvector,others,kubeadm_"$KUBE_RELEASE"}

  echo - create image dir
  cd /opt/k8s/images/

  echo - rancher image list 
  curl -#L https://github.com/rancher/rancher/releases/download/v$RANCHER_VERSION/rancher-images.txt -o rancher/orig_rancher-images.txt

  echo - shorten rancher list with a sort
  # fix library tags
  # sed -i -e '0,/busybox/s/busybox/library\/busybox/' -e 's/registry/library\/registry/g' rancher/orig_rancher-images.txt
  
  # remove things that are not needed and overlapped
  sed -E '/neuvector|minio|gke|aks|eks|sriov|harvester|mirrored|longhorn|thanos|tekton|istio|hyper|jenkins|windows/d' rancher/orig_rancher-images.txt > rancher/cleaned_orig_rancher-images.txt

  # capi fixes
  grep cluster-api rancher/orig_rancher-images.txt >> rancher/cleaned_orig_rancher-images.txt

  # get latest version
  for i in $(cat rancher/cleaned_orig_rancher-images.txt|awk -F: '{print $1}'); do 
    grep -w "$i" rancher/cleaned_orig_rancher-images.txt | sort -Vr| head -1 >> rancher/version_unsorted.txt
  done

  grep rancher/kubectl rancher/orig_rancher-images.txt >> rancher/version_unsorted.txt

  # final sort
  sort -u rancher/version_unsorted.txt > rancher/rancher-images.txt

  echo - Cert-manager image list
  helm template /opt/k8s/helm/cert-manager-$CERT_VERSION.tgz | awk '$1 ~ /image:/ {print $2}' | sed s/\"//g > cert/cert-manager-images.txt

  echo - longhorn image list
  curl -#L https://raw.githubusercontent.com/longhorn/longhorn/v$LONGHORN_VERSION/deploy/longhorn-images.txt -o longhorn/longhorn-images.txt

  echo - neuvector image list
  helm template /opt/k8s/helm/core-$NEU_VERSION.tgz | awk '$1 ~ /image:/ {print $2}' | sed -e 's/\"//g' > neuvector/neuvector-images.txt

  echo - other image list
  curl -#L https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/other-images.txt -o others/other-images.txt

  echo - Login docker for upload images
  echo { > /etc/docker/daemon.json
  echo '    "insecure-registries" : [ "hostip:5000" ]' >> /etc/docker/daemon.json
  echo } >> /etc/docker/daemon.json
  sed -i "s/hostip/$BUILD_SERVER_IP/g" /etc/docker/daemon.json

  systemctl restart docker
  docker login -u admin -p admin@2675 $BUILD_SERVER_IP:5000

  echo - Load images for Mongo Redis Registry
  crane --insecure copy mongo:latest $BUILD_SERVER_IP:5000/mongo:latest
  crane --insecure copy redis:latest $BUILD_SERVER_IP:5000/redis:latest
  crane --insecure copy registry:latest $BUILD_SERVER_IP:5000/registry:latest
  crane --insecure copy debian:9 $BUILD_SERVER_IP:5000/debian:9
  crane --insecure copy k8s.gcr.io/addon-resizer:1.7 $BUILD_SERVER_IP:5000/addon-resizer:1.7
  crane --insecure copy prom/alertmanager:v0.16.2 $BUILD_SERVER_IP:5000/prometheus/alertmanager:v0.16.0
  crane --insecure copy docker.io/busybox:latest $BUILD_SERVER_IP:5000/busybox:latest

  echo - Load images for Longhorn
  for i in $(cat /opt/k8s/images/longhorn/longhorn-images.txt); do
    img=$(echo $i | cut -d'/' -f2)
    pkg=$(echo $i | cut -d'/' -f1)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for CertManager
  for i in $(cat /opt/k8s/images/cert/cert-manager-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for Neuvector
  for i in $(cat /opt/k8s/images/neuvector/neuvector-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for Rancher
  for i in $(cat /opt/k8s/images/rancher/rancher-images.txt); do
    img=$(echo $i | cut -d'/' -f2)
    pkg=$(echo $i | cut -d'/' -f1)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for Monitoring Logging Auth Dashboard Nginx
  for i in $(cat /opt/k8s/images/others/other-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - Verify Image Upload
  crane --insecure catalog $BUILD_SERVER_IP:5000

}

################################# build ################################
function build () {

  if [[ -z "$BUILD_SERVER_IP" ]]; then 
   echo - Please enter Build Server IP in variable
   exit
  fi
  
  echo - skopeo
  if ! command -v docker &> /dev/null;
  then
    echo - Installing skopeo
    yum install -y skopeo
  fi

  echo - Installing packages
  mkdir -p /root/registry/data/auth
  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   apt update -y
   apt install -y apt-transport-https ca-certificates gpg nfs-common curl wget git net-tools unzip jq zip nmap telnet dos2unix ldap-utils haproxy apparmor nfs-kernel-server
  else
   chcon system_u:object_r:container_file_t:s0 /root/registry/data
   yum install -y git curl wget openldap openldap-clients bind-utils jq httpd-tools haproxy zip unzip go nmap telnet dos2unix zstd nfs-utils iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils 
  fi

  echo - "Install docker, crane & setup docker private registry"
  if ! command -v docker &> /dev/null;
  then
    echo "Trying to Install Docker..."
    if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
      apt update -y && apt install docker.io -y
      systemctl start docker; systemctl enable docker
    else
      curl -s https://releases.rancher.com/install-docker/19.03.sh | sh
      systemctl start docker; systemctl enable docker
    fi
  fi 
  systemctl restart docker

  if ! command -v crane &> /dev/null;
  then
    echo "Trying to Install Crane..."
    curl -sL "https://github.com/google/go-containerregistry/releases/download/v0.19.0/go-containerregistry_Linux_x86_64.tar.gz" > go-containerregistry.tar.gz
    tar -zxvf go-containerregistry.tar.gz -C /usr/local/bin/ crane
  fi 

  if ! command -v kubectl &> /dev/null;
  then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && chmod 755 kubectl && mv kubectl /usr/local/bin/
  fi 

  mkdir -p /root/registry/data/certs
  certgen
  cp domain.key /root/registry/data/certs/domain.key
  cp domain.crt /root/registry/data/certs/domain.crt

  echo - Private Registry Setup
  if ! test -f /root/registry/data/auth/htpasswd; then
    docker run --name htpass --entrypoint htpasswd httpd:2 -Bbn admin admin@2675 > /root/registry/data/auth/htpasswd  
    docker rm htpass
  fi

  PR=`docker ps -a -q -f name=private-registry`
  if [[ $PR == "" ]]; then
    docker run -itd -p 5000:5000 --restart=always --name private-registry \
    -v /root/registry/data/auth:/auth -v /root/registry/data:/var/lib/registry \
    -v /root/registry/data/certs:/certs -v /root/registry/data/certs:/certs \
    -e REGISTRY_AUTH=htpasswd -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
    registry
  fi

  mkdir -p /opt/k8s/{k8s_$KUBE_RELEASE,helm} /opt/k8s/images/{cert,rancher,longhorn,registry,flask,neuvector,others,kubeadm_"$KUBE_RELEASE"}
  cd /opt/k8s/k8s_$KUBE_RELEASE/

cat <<EOF > /opt/k8s/k8s_$KUBE_RELEASE/registries.conf
[registries.search]
registries = ['$BUILD_SERVER_IP:5000']

[registries.insecure]
registries = ['$BUILD_SERVER_IP:5000']
EOF

  echo -e "\nDownload Containerd Package RPMs"
  curl -O https://download.docker.com/linux/centos/8/${ARCH}/stable/Packages/docker-ce-cli-23.0.6-1.el8.${ARCH}.rpm
  curl -O https://download.docker.com/linux/centos/8/${ARCH}/stable/Packages/containerd.io-1.6.9-3.1.el8.${ARCH}.rpm
  curl -O https://download.docker.com/linux/centos/8/${ARCH}/stable/Packages/docker-compose-plugin-2.17.3-1.el8.${ARCH}.rpm
  curl -O https://download.docker.com/linux/centos/8/${ARCH}/stable/Packages/docker-ce-rootless-extras-23.0.6-1.el8.${ARCH}.rpm
  curl -O https://download.docker.com/linux/centos/8/${ARCH}/stable/Packages/docker-ce-23.0.6-1.el8.${ARCH}.rpm
  curl -O http://mirror.centos.org/centos/8-stream/BaseOS/${ARCH}/os/Packages/libcgroup-0.41-19.el8.${ARCH}.rpm

  echo -e "\nDownload Kubernetes Binaries"
  curl -L -O "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${K8s_ARCH}-${CNI_PLUGINS_VERSION}.tgz"
  curl -L -O "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${K8s_ARCH}.tar.gz"
  curl -L --remote-name-all https://dl.k8s.io/release/${KUBE_RELEASE}/bin/linux/${K8s_ARCH}/{kubeadm,kubelet}
  curl -L -O "https://raw.githubusercontent.com/kubernetes/release/${RELEASE_VERSION}/cmd/kubepkg/templates/latest/deb/kubelet/lib/systemd/system/kubelet.service"
  curl -L -O "https://raw.githubusercontent.com/kubernetes/release/${RELEASE_VERSION}/cmd/kubepkg/templates/latest/deb/kubeadm/10-kubeadm.conf"
  curl -L -O "https://dl.k8s.io/release/${KUBE_RELEASE}/bin/linux/${K8s_ARCH}/kubectl"

  echo -e "\nDownload dependencies"
  curl -O https://www.rpmfind.net/linux/centos/8-stream/AppStream/${ARCH}/os/Packages/socat-1.7.3.3-2.el8.${ARCH}.rpm
  curl -O http://mirror.centos.org/centos/8-stream/BaseOS/${ARCH}/os/Packages/conntrack-tools-1.4.4-11.el8.${ARCH}.rpm
  curl -LO "https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_${K8s_ARCH}.tar.gz"

  echo -e "\nDownload CRIO Package"
  curl -LO https://storage.googleapis.com/cri-o/artifacts/cri-o.amd64.c0b2474b80fd0844b883729bda88961bed7b472b.tar.gz

  echo - Checking helm 
  if ! command -v helm &> /dev/null;
  then
   echo - Get Helm Charts
   cd /opt/k8s/helm/
   echo - get helm
   curl -#LO https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
   rm -rf linux-amd64 > /dev/null 2>&1
  fi

  echo - Get Moitoring and Logging 
  cd /opt/k8s/images/others/
  wget -q https://raw.githubusercontent.com/cloudcafetech/AI-for-K8S/main/kubemon.yaml
  wget -q https://github.com/cloudcafetech/kubesetup/raw/master/monitoring/dashboard/pod-monitoring.json
  wget -q https://github.com/cloudcafetech/kubesetup/raw/master/monitoring/dashboard/kube-monitoring-overview.json
  wget -q https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/kubelog.yaml
  wget -q https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/loki.yaml
  mv loki.yaml loki.yaml-minio-s3
  wget -q https://raw.githubusercontent.com/cloudcafetech/kubesetup/master/logging/loki.yaml
  mv loki.yaml loki.yaml-local-filesystem  
  wget -q https://raw.githubusercontent.com/cloudcafetech/kubesetup/master/logging/promtail.yaml
  sed -i "s/34.125.24.130/$BUILD_SERVER_PUBIP/g" kubemon.yaml
  sed -i -e "s/quay.io/$BUILD_SERVER_IP:5000/g" -e "s/k8s.gcr.io/$BUILD_SERVER_IP:5000/g" kubemon.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" kubemon.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" kubelog.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" promtail.yaml

  echo - Get Storage 
  wget -q https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/minio.yaml
  wget -q https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/local-path-storage.yaml
  sed -i -e "s/quay.io/$BUILD_SERVER_IP:5000/g" minio.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" local-path-storage.yaml
  sed -i "s/34.125.24.130/$BUILD_SERVER_PUBIP/g" minio.yaml

  echo - Get Certmanager 
  wget -q https://github.com/cert-manager/cert-manager/releases/download/$CERT_VERSION/cert-manager.yaml 
  sed -i -e "s/quay.io/$BUILD_SERVER_IP:5000/g" cert-manager.yaml

  echo - Get Networking and Routing 
  wget -q https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/kube-flannel.yml
  wget -q https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/ingress-controller.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" kube-flannel.yml
  sed -i -e "s/registry.k8s.io/$BUILD_SERVER_IP:5000/g" ingress-controller.yaml

  echo - Get Kubeadm images
  cd /opt/k8s/images/kubeadm_"$KUBE_RELEASE"
  for image in "${images[@]}"; do
    docker pull "$image"
    image_name=$(echo "$image" | sed 's|/|_|g' | sed 's/:/_/g')
    docker save -o "${image_name}.tar" "$image"
  done
  tar -cvzf kube-image.tar.gz *.tar

  echo - Download NFS Packages for Ubuntu 20.04 
  mkdir -p /root/ubuntu-repo/pkg
  if [ ! -f /root/ubuntu-repo/nfs-common_1.3.4-2.5ubuntu3_amd64.deb ]; then
    cd /root/ubuntu-repo/
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/n/nfs-utils/nfs-common_1.3.4-2.5ubuntu3_amd64.deb
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/libn/libnfsidmap/libnfsidmap2_0.25-5.1ubuntu1_amd64.deb
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/libt/libtirpc/libtirpc3_1.2.5-1_amd64.deb
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/r/rpcbind/rpcbind_1.2.5-8_amd64.deb
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/k/keyutils/keyutils_1.6-6ubuntu1_amd64.deb
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/libt/libtirpc/libtirpc-common_1.2.5-1_all.deb
    curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/n/nfs-utils/nfs-kernel-server_1.3.4-2.5ubuntu3_amd64.deb
    curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/nfs_offline_install.sh
    sed -i "s/10.182.15.216/$BUILD_SERVER_IP/g" nfs_offline_install.sh
    tar -cvzf nfs-pkg.tar.gz *.deb
    cd
  fi 

  echo - Download Kube Packages for Ubuntu 20.04 
  if [ ! -f /root/ubuntu-repo/pkg/kubectl*.deb ]; then
    chcon system_u:object_r:container_file_t:s0 /root/ubuntu-repo/pkg
    cd /root/ubuntu-repo/pkg
    curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/ubuntu-kubeadm-pkg.sh
    chmod 755 ubuntu-kubeadm-pkg.sh
    docker rm ubuntu
    docker run --name ubuntu -it -e K8S=$K8S_VER_MJ -v /root/ubuntu-repo/pkg:/host ubuntu:20.04 bash -c "$(cat ./ubuntu-kubeadm-pkg.sh)"
    sleep 10
    docker rm ubuntu
    cd crio
    tar -cvzf kube-crio-pkg.tar.gz *.deb
    cp kube-crio-pkg.tar.gz /root/ubuntu-repo/
    cd ../cond
    tar -cvzf kube-cond-pkg.tar.gz *.deb
    cp kube-cond-pkg.tar.gz /root/ubuntu-repo/
  fi 

  echo - Setup nfs
  # share out opt directory
  mkdir /mnt/common
  #chown nobody:nobody /mnt/common
  #chown nobody:nogroup /mnt/common
  chmod 777 /mnt/common
  echo "/mnt/common *(rw)" >> /etc/exports
  echo "/opt/k8s *(ro)" >> /etc/exports
  echo "/root/ubuntu-repo *(ro)" >> /etc/exports
  systemctl enable nfs-server.service && systemctl start nfs-server.service
  systemctl enable nfs-kernel-server && systemctl start nfs-kernel-server && systemctl restart nfs-kernel-server
 
  echo - Download CentOS 8 ISO
  cd /opt/k8s
  if [[ ! -f CentOS-Stream-8-x86_64-latest-dvd1.iso ]]; then 
   wget http://isoredirect.centos.org/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso
  fi

  #imageupload
  #websetup
  #lbsetup
  #compressall

}

################################# base ################################
function base () {
# install all the base bits.

  echo - Disable swap
  sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
  swapoff -a

cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
 
  modprobe overlay
  modprobe br_netfilter

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

  sysctl --system
  lsmod | grep br_netfilter
  lsmod | grep overlay
  sysctl net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.ipv4.ip_forward

  # Download from Build server
  if [ ! -d /opt/k8s ]; then
   mkdir /opt/k8s
  fi

  #mount $BUILD_SERVER_IP:/opt/k8s /opt/k8s

  if [ ! -d /opt/k8s/k8s_"$KUBE_RELEASE" ]; then
     mkdir /opt/k8s/k8s_"$KUBE_RELEASE"
  fi

  echo - Get Kubeadm images and packages
  cd /opt/k8s/k8s_"$KUBE_RELEASE"
  mkdir images pkg
  curl -#OL http://$BUILD_SERVER_IP:8080/kubeadm_"$KUBE_RELEASE"/kube-image.tar.gz
  cd images
  cp /opt/k8s/k8s_"$KUBE_RELEASE"/kube-image.tar.gz .
  tar -zxvf kube-image.tar.gz

  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
  # For Debian Distribution
   echo - Stopping and disabling firewall 
   systemctl stop ufw
   systemctl stop apparmor.service
   systemctl disable --now ufw
   systemctl disable --now apparmor.service 
   echo - Installing NFS tools
   mkdir /opt/k8s/k8s_"$KUBE_RELEASE"/nfspkg
   cd /opt/k8s/k8s_"$KUBE_RELEASE"/nfspkg
   #curl -#OL http://$BUILD_SERVER_IP:8080/ubuntu-repo/nfs_offline_install.sh && chmod 755 nfs_offline_install.sh
   #./nfs_offline_install.sh
   curl -#OL http://$BUILD_SERVER_IP:8080/ubuntu-repo/nfs-pkg.tar.gz
   tar -zxvf nfs-pkg.tar.gz
   sleep 5
   dpkg -i *.deb
   echo - Installing CNI tool
   if [[ "$K8SCNI" == "CRIO" ]]; then
     cd /opt/k8s/k8s_"$KUBE_RELEASE"/pkg
     curl -#OL http://$BUILD_SERVER_IP:8080/ubuntu-repo/kube-crio-pkg.tar.gz
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/registries.conf
     tar -zxvf kube-crio-pkg.tar.gz
     rm -rf openssl* 
     dpkg -i *.deb
     sleep 5
     apt-mark hold kubelet kubeadm kubectl
     sed -i 's|# cgroup_manager = "systemd"|  cgroup_manager = "systemd"|g' /etc/crio/crio.conf
     sed -i 's|# pause_image = "registry.k8s.io/pause:3.6"|  pause_image = "registry.k8s.io/pause:3.9"|g' /etc/crio/crio.conf

     # Due to technical challenges not able modify in one liner command, use 3 below command
     sed -i '/insecure_registries =/a   insecure_registries = [ "RSERVERIP:5000" ]' /etc/crio/crio.conf
     sed -i "s/RSERVERIP/$BUILD_SERVER_IP/g" /etc/crio/crio.conf
     sed -i 's|insecure_registries|  insecure_registries|g' /etc/crio/crio.conf

     cp /etc/containers/registries.conf /etc/containers/registries.conf_ori
     cp registries.conf /etc/containers/registries.conf
     echo "runtime-endpoint: unix:///run/crio/crio.sock" > /etc/crictl.yaml
     systemctl enable crio --now
     systemctl restart crio
     echo - Private registry login
     podman login -u admin -p admin@2675 $BUILD_SERVER_IP:5000
   else
     cd /opt/k8s/k8s_"$KUBE_RELEASE"/pkg
     curl -#OL http://$BUILD_SERVER_IP:8080/ubuntu-repo/kube-cond-pkg.tar.gz
     tar -zxvf kube-cond-pkg.tar.gz
     rm -rf openssl* 
     dpkg -i *.deb
     sleep 5
     apt-mark hold kubelet kubeadm kubectl
     rm -rf /etc/containerd/config.toml 
     mkdir -p /etc/containerd
     containerd config default > /etc/containerd/config.toml 
     sed -i -e 's\            SystemdCgroup = false\            SystemdCgroup = true\g' /etc/containerd/config.toml
     sed -i 's|    sandbox_image = "registry.k8s.io/pause:3.6"|    sandbox_image = "registry.k8s.io/pause:3.9"|g' /etc/containerd/config.toml
     sed -i 's/^disabled_plugins = \["cri"\]/#&/' /etc/containerd/config.toml
     sed -i 's/plugins."io.containerd.grpc.v1.cri".registry.configs/plugins."io.containerd.grpc.v1.cri".registry.configs."RSERVERIP:5000".tls/' /etc/containerd/config.toml
     sed -i '/registry.configs/a insecure_skip_verify = true' /etc/containerd/config.toml
     sed -i 's/insecure_skip_verify/         insecure_skip_verify/' /etc/containerd/config.toml
     sed -i 's/plugins."io.containerd.grpc.v1.cri".registry.auths/plugins."io.containerd.grpc.v1.cri".registry.configs."RSERVERIP:5000".auth/' /etc/containerd/config.toml 
     sed -i 's/plugins."io.containerd.grpc.v1.cri".registry.mirrors/plugins."io.containerd.grpc.v1.cri".registry.mirrors."RSERVERIP:5000"/' /etc/containerd/config.toml
     sed -i '/auth/a username = "admin"' /etc/containerd/config.toml
     sed -i '/username/a password = "admin@2675"' /etc/containerd/config.toml 
     sed -i 's/username/         username/' /etc/containerd/config.toml
     sed -i 's/password/         password/' /etc/containerd/config.toml
     sed -i '/registry.mirrors/a endpoint = ["https://RSERVERIP:5000"]' /etc/containerd/config.toml
     sed -i 's/endpoint/         endpoint/' /etc/containerd/config.toml
     sed -i "s/RSERVERIP/$BUILD_SERVER_IP/g" /etc/containerd/config.toml
     systemctl enable --now containerd
     systemctl restart containerd
     echo "runtime-endpoint: unix:///run/containerd/containerd.sock" > /etc/crictl.yaml
   fi 
  else
   # For RedHat Distribution
   echo - Stopping disabling firewalld and SELinux
   systemctl stop firewalld; systemctl disable firewalld
   setenforce 0
   sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
   echo - Installing required packages
   curl -OL http://$BUILD_SERVER_IP:8080/iso/centos8-remote.repo
   rm -rf /etc/yum.repos.d/* 
   cp centos8-remote.repo /etc/yum.repos.d/centos8.repo
   chmod 644 /etc/yum.repos.d/centos8.repo
   yum install -y git curl wget bind-utils jq httpd-tools zip unzip nfs-utils go nmap telnet dos2unix zstd iscsi-initiator-utils iptables iproute-tc

   if [[ "$K8SCNI" == "CRIO" ]]; then
     yum install -y conntrack socat podman
     cd /opt/k8s/k8s_"$KUBE_RELEASE"/
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/cri-o.amd64.c0b2474b80fd0844b883729bda88961bed7b472b.tar.gz
     tar -zxvf cri-o.amd64.c0b2474b80fd0844b883729bda88961bed7b472b.tar.gz
     cd cri-o
     ./install
     cd /opt/k8s/k8s_"$KUBE_RELEASE"/
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/registries.conf
     cp /etc/containers/registries.conf /etc/containers/registries.conf_ori
     cp registries.conf /etc/containers/registries.conf
cat <<EOF > /etc/crio/crio.conf.d/10-crun.conf
[crio.runtime]
default_runtime = "crun"
cgroup_manager = "systemd"

[crio.runtime.runtimes.crun]
allowed_annotations = [
    "io.containers.trace-syscall",
]

[crio.image]
pause_image = "registry.k8s.io/pause:3.9"

insecure_registries = [ '$BUILD_SERVER_IP:5000' ]
EOF
     sleep 5
     systemctl daemon-reload;systemctl start crio; systemctl enable crio --now
     #echo "runtime-endpoint: unix:///run/crio/crio.sock" > /etc/crictl.yaml
     systemctl restart crio
     echo - Private registry login
     podman login -u admin -p admin@2675 $BUILD_SERVER_IP:5000
   else
     cd /opt/k8s/k8s_"$KUBE_RELEASE"
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/cni-plugins-linux-${K8s_ARCH}-v1.3.0.tgz
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/crictl-v1.27.0-linux-${K8s_ARCH}.tar.gz
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/docker-ce-cli-23.0.6-1.el8.${ARCH}.rpm
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/containerd.io-1.6.9-3.1.el8.${ARCH}.rpm
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/docker-compose-plugin-2.17.3-1.el8.${ARCH}.rpm
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/docker-ce-rootless-extras-23.0.6-1.el8.${ARCH}.rpm
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/docker-ce-23.0.6-1.el8.${ARCH}.rpm
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/libcgroup-0.41-19.el8.${ARCH}.rpm     
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/socat-1.7.3.3-2.el8.${ARCH}.rpm
     curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/conntrack-tools-1.4.4-11.el8.${ARCH}.rpm
     dnf -y install ./*.rpm
     mkdir -p /opt/cni/bin
     tar -C /opt/cni/bin -xz -f "cni-plugins-linux-${K8s_ARCH}-v1.3.0.tgz"
     tar -C /usr/local/bin -xz -f "crictl-v1.27.0-linux-${K8s_ARCH}.tar.gz"
     rm -rf /etc/containerd/config.toml 
     mkdir -p /etc/containerd
     containerd config default > /etc/containerd/config.toml 
     sed -i -e 's\            SystemdCgroup = false\            SystemdCgroup = true\g' /etc/containerd/config.toml
     sed -i 's|    sandbox_image = "registry.k8s.io/pause:3.6"|    sandbox_image = "registry.k8s.io/pause:3.9"|g' /etc/containerd/config.toml
     sed -i 's/^disabled_plugins = \["cri"\]/#&/' /etc/containerd/config.toml
     sed -i 's/plugins."io.containerd.grpc.v1.cri".registry.configs/plugins."io.containerd.grpc.v1.cri".registry.configs."RSERVERIP:5000".tls/' /etc/containerd/config.toml
     sed -i '/registry.configs/a insecure_skip_verify = true' /etc/containerd/config.toml
     sed -i 's/insecure_skip_verify/         insecure_skip_verify/' /etc/containerd/config.toml
     sed -i 's/plugins."io.containerd.grpc.v1.cri".registry.auths/plugins."io.containerd.grpc.v1.cri".registry.configs."RSERVERIP:5000".auth/' /etc/containerd/config.toml
     sed -i 's/plugins."io.containerd.grpc.v1.cri".registry.mirrors/plugins."io.containerd.grpc.v1.cri".registry.mirrors."RSERVERIP:5000"/' /etc/containerd/config.toml
     sed -i '/auth/a username = "admin"' /etc/containerd/config.toml
     sed -i '/username/a password = "admin@2675"' /etc/containerd/config.toml 
     sed -i 's/username/         username/' /etc/containerd/config.toml
     sed -i 's/password/         password/' /etc/containerd/config.toml
     sed -i '/registry.mirrors/a endpoint = ["https://RSERVERIP:5000"]' /etc/containerd/config.toml
     sed -i 's/endpoint/         endpoint/' /etc/containerd/config.toml
     sed -i "s/RSERVERIP/$BUILD_SERVER_IP/g" /etc/containerd/config.toml
     systemctl enable --now containerd
     echo "runtime-endpoint: unix:///run/containerd/containerd.sock" > /etc/crictl.yaml
   fi 

   cd /opt/k8s/k8s_"$KUBE_RELEASE"
   curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/kubeadm
   curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/kubectl
   curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/kubelet
   curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/10-kubeadm.conf
   chmod +x kubeadm kubelet kubectl
   mv kubeadm kubelet kubectl /usr/local/bin
   mkdir -p /etc/systemd/system/kubelet.service.d
   sed "s:/usr/bin:/usr/local/bin:g" 10-kubeadm.conf > /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
cat <<EOF > /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet

[Service]
ExecStartPre=/usr/bin/mkdir -p /etc/kubernetes/manifests
ExecStart=/usr/local/bin/kubelet
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable --now kubelet
    # Due to missing file (/run/systemd/resolve/resolv.conf) error 
    if [[ ! -f /run/systemd/resolve/resolv.conf ]]; then 
      mkdir /run/systemd/resolve
      cp /etc/resolv.conf /run/systemd/resolve/resolv.conf 
    fi

  fi

   echo - Import K8S Images
   cd /opt/k8s/k8s_"$KUBE_RELEASE/images"
   for image in "${images[@]}"; do
    tarfile=`echo "$image" | sed -e "s:/:_:g" | sed -e "s/:/_/g"`
    if [[ -f "$tarfile.tar" ]]; then
      if [[ "$K8SCNI" == "CRIO" ]]; then
        podman load -i "$tarfile".tar
      else
        ctr -n k8s.io images import "$tarfile".tar
      fi
    else
      echo "File "$tarfile".tar not found!" 1>&2
    fi
   done

}

################################# Deploy Master 1 ################################
function deploy_control1 () {
  # this is for the first node

  if [[ -z "$MASTERIP1" ]]; then 
   echo - Please enter Master1 IP in variable
   exit
  fi

  base

  # Setting up Kubernetes Master using Kubeadm
  sleep 10
  mkdir /mnt/join
  mount $BUILD_SERVER_IP:/mnt/common /mnt/join
  if [[ -z "$LB_IP" ]]; then LB_IP=$MASTERIP1; fi
  #kubeadm init --token=$TOKEN --pod-network-cidr=10.244.0.0/16 --kubernetes-version $KUBE_RELEASE --control-plane-endpoint "$LB_IP:6443" --upload-certs --ignore-preflight-errors=all
  kubeadm init --token=$TOKEN --pod-network-cidr=10.244.0.0/16 --kubernetes-version $KUBE_RELEASE --control-plane-endpoint "$LB_IP:6443" --upload-certs --ignore-preflight-errors=all | grep -Ei "kubeadm join|discovery-token-ca-cert-hash|certificate-key" 2>&1 | tee kubeadm-output.txt
  cp kubeadm-output.txt /mnt/join/
  sleep 30
  mkdir $HOME/.kube
  cp /etc/kubernetes/admin.conf $HOME/.kube/config
  chown $(id -u):$(id -g) $HOME/.kube/config
  export KUBECONFIG=$HOME/.kube/config
  echo "export KUBECONFIG=$HOME/.kube/config" >> $HOME/.bash_profile
  echo "alias oc=/usr/bin/kubectl" >> /root/.bash_profile
  chmod 600 $HOME/.kube/config
  cp $HOME/.kube/config /home/k8s-aws/
  chown k8s-aws:k8s-aws /home/k8s-aws/config
 
  sleep 5

  echo - Deploy Container Networking and Routing
  cd /opt/k8s/k8s_"$KUBE_RELEASE"
  curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/kube-flannel.yml
  kubectl create -f kube-flannel.yml
  #curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/ingress-controller.yaml
  #kubectl create -f ingress-controller.yaml  

  echo - unpack helm
  mkdir /mnt/test
  mount $BUILD_SERVER_IP:/opt/k8s /mnt/test
  #cp /mnt/test/helm/helm-v3.13.2-linux-amd64.tar.gz .
  cd /opt/k8s/k8s_"$KUBE_RELEASE"
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1

  source ~/.bashrc

}

################################# Deploy Master 2 & 3 ################################
function deploy_control23 () {
  # this is for the 2nd & 3rd Master node

  if [[ -z "$MASTERIP1" ]]; then 
   echo - Please enter Master1 IP in variable
   exit
  fi

  base

  echo - Setting up Kubernetes Master2 and Master3 using Kubeadm
  sleep 10
  mkdir /mnt/join
  mount $BUILD_SERVER_IP:/mnt/common /mnt/join
  CERTKEY=$(more /mnt/join/kubeadm-output.txt | grep certificate-key | sed -n 's/--control-plane --certificate-key//p')
  HASHKEY=$(more /mnt/join/kubeadm-output.txt | grep discovery-token-ca-cert-hash | tail -1 | sed -n 's/--discovery-token-ca-cert-hash//p')
  if [[ -z "$LB_IP" ]]; then LB_IP=$MASTERIP1; fi
  kubeadm join $LB_IP:6443 --token $TOKEN --discovery-token-ca-cert-hash $HASHKEY --control-plane --certificate-key $CERTKEY --ignore-preflight-errors=all
  sleep 40

  echo - unpack helm
  mkdir /mnt/test
  mount $BUILD_SERVER_IP:/opt/k8s /mnt/test
  #cp /mnt/test/helm/helm-v3.13.2-linux-amd64.tar.gz .
  cd /opt/k8s/k8s_"$KUBE_RELEASE"
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
  
  mkdir $HOME/.kube
  cp /etc/kubernetes/admin.conf $HOME/.kube/config
  chown $(id -u):$(id -g) $HOME/.kube/config
  export KUBECONFIG=$HOME/.kube/config
  echo "export KUBECONFIG=$HOME/.kube/config" >> $HOME/.bash_profile
  echo "alias oc=/usr/bin/kubectl" >> /root/.bash_profile
  chmod 600 $HOME/.kube/config
  cp $HOME/.kube/config /home/k8s-aws/
  chown k8s-aws:k8s-aws /home/k8s-aws/config

  echo "------------------------------------------------------------------"

}

################################# deploy worker ################################
function deploy_worker () {
  echo - deploy worker

  if [[ -z "$MASTERIP1" ]]; then 
   echo - Please enter Master1 IP in variable
   exit
  fi

  base

  # Delete unwanted images
  cd /opt/k8s/k8s_"$KUBE_RELEASE/images"
  rm -rf *etcd*.tar *kube-apiserver*.tar *controller*.tar *scheduler*.tar 
  podman rmi $(podman images | grep -E 'apiserver|controller|scheduler|etcd' | awk '{print $3}') -f
  crictl rmi $(crictl images | grep -E 'apiserver|controller|scheduler|etcd' | awk '{print $3}') 
  echo - Setting up Kubernetes Worker using Kubeadm
  sleep 10
  mkdir /mnt/join
  mount $BUILD_SERVER_IP:/mnt/common /mnt/join
  HASHKEY=$(more /mnt/join/kubeadm-output.txt | grep discovery-token-ca-cert-hash | tail -1 | sed -n 's/--discovery-token-ca-cert-hash//p')
  if [[ -z "$LB_IP" ]]; then LB_IP=$MASTERIP1; fi
  kubeadm join $LB_IP:6443 --token $TOKEN --discovery-token-ca-cert-hash $HASHKEY --ignore-preflight-errors=all
  sleep 20
  #kubeadm join $LB_IP:6443 --token=$TOKEN --discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=all

  echo "------------------------------------------------------------------"

}

################## Cluster login from Build Server #####################
function kubelogin () {
  echo - Kubernetes login setup
  #scp -i /root/.gcp.pem k8s-aws@$MASTERIP1>:/home/k8s-aws/config .
  mkdir $HOME/.kube
  cp config $HOME/.kube/config
  chown $(id -u):$(id -g) $HOME/.kube/config
  export KUBECONFIG=$HOME/.kube/config
  echo "export KUBECONFIG=$HOME/.kube/config" >> $HOME/.bash_profile
  echo "alias oc=/usr/local/bin/kubectl" >> /root/.bash_profile

}

################################# flask ################################
function flask () {
  # dummy 3 tier app - asked for by a customer. 
  echo - load images
  for file in $(ls /opt/k8s/images/flask/ | grep -v yaml ); do 
     skopeo copy docker-archive:/opt/k8s/images/flask/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk '{print "$BUILD_SERVER_IP:5000/flask/"$1}')" --dest-tls-verify=false
  done

  echo "------------------------------------------------------------------"
  echo " to deploy: "
  echo "   edit /opt/rancher/images/flask/flask.yaml to the ingress URL."
  echo "   kubectl apply -f /opt/rancher/images/flask/flask.yaml"
  echo "------------------------------------------------------------------"

}

############################# Cert Manager ################################
function certman () {
  # deploy Cert Manager with private registry images
  cd /opt/k8s/images/others/
  echo - Cert Manager Setup
  kubectl create -f cert-manager.yaml
}

####################### Nginx Ingress Controller ###########################
function ingcon () {
  # Deploy Nginx Ingress Controller
  cd /opt/k8s/images/others/
  echo - Deploy Nginx Ingress Controller
  kubectl taint node $MASTERDNS1 node-role.kubernetes.io/control-plane:NoSchedule-
  kubectl taint node $MASTERDNS2 node-role.kubernetes.io/control-plane:NoSchedule-
  kubectl taint node $MASTERDNS3 node-role.kubernetes.io/control-plane:NoSchedule-

  kubectl label nodes $MASTERDNS1 zone=master
  kubectl label nodes $MASTERDNS2 zone=master
  kubectl label nodes $MASTERDNS3 zone=master

  kubectl create -f ingress-controller.yaml
  kubectl scale deployment.apps/ingress-nginx-controller -n ingress-nginx --replicas=3
}

###################### Monitoring And Logging #############################
function monlog () {
  # deploy Monitoring & Logging with private registry images
  cd /opt/k8s/images/others/

  echo - Kubernetes Storage Setup
  kubectl create -f local-path-storage.yaml
  sleep 10
  kubectl create -f minio.yaml

  echo - Kubernetes Monitoring Setup
  kubectl create ns monitoring
  kubectl create configmap grafana-dashboards -n monitoring --from-file=pod-monitoring.json --from-file=kube-monitoring-overview.json
  kubectl create -f kubemon.yaml -n monitoring

  echo - Kubernetes Logging Setup
  kubectl create ns logging
  cp loki.yaml-minio-s3 loki.yaml 
  #cp loki.yaml-local-filesystem loki.yaml 
  kubectl create secret generic loki -n logging --from-file=loki.yaml
  kubectl create -f kubelog.yaml -n logging
  kubectl delete ds loki-fluent-bit-loki -n logging
  kubectl create -f promtail.yaml -n logging

}

################################# longhorn ################################
function longhorn () {
  # deploy longhorn with private registry images
  echo - deploying longhorn
  helm upgrade -i longhorn /opt/k8s/helm/longhorn-$LONGHORN_VERSION.tgz --namespace longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.$DOMAIN --set global.cattle.systemDefaultRegistry=$BUILD_SERVER_IP:5000
}

################################# neuvector ################################
function neuvector () {
  # deploy neuvector with private registry images
  echo - deploying neuvector
  helm upgrade -i neuvector --namespace neuvector /opt/k8s/helm/core-$NEU_VERSION.tgz --create-namespace  --set imagePullSecrets=regsecret --set k3s.enabled=true --set k3s.runtimePath=/run/k3s/containerd/containerd.sock  --set manager.ingress.enabled=true --set controller.pvc.enabled=true --set manager.svc.type=ClusterIP --set controller.pvc.capacity=500Mi --set registry=$BUILD_SERVER_IP:5000 --set controller.image.repository=neuvector/controller --set enforcer.image.repository=neuvector/enforcer --set manager.image.repository=neuvector/manager --set cve.updater.image.repository=neuvector/updater --set manager.ingress.host=neuvector.$DOMAIN --set internal.certmanager.enabled=true
}

################################# rancher ################################
function rancher () {
  # deploy rancher with local helm/images
  echo - deploying rancher
  helm upgrade -i cert-manager /opt/k8s/helm/cert-manager-$CERT_VERSION.tgz --namespace cert-manager --create-namespace --set installCRDs=true --set image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-controller --set webhook.image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-webhook --set cainjector.image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-cainjector --set startupapicheck.image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-ctl 

  helm upgrade -i rancher /opt/k8s/helm/rancher-$RANCHER_VERSION.tgz --namespace cattle-system --create-namespace --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set useBundledSystemChart=true --set rancherImage=$BUILD_SERVER_IP:5000/rancher/rancher --set systemDefaultRegistry=$BUILD_SERVER_IP:5000 --set hostname=rancher.$DOMAIN

  echo "   - bootstrap password = \"bootStrapAllTheThings\" "
}

################################# validate ################################
function validate () {
  echo - showing images
  kubectl get pods -A -o jsonpath="{.items[*].spec.containers[*].image}" | tr -s '[[:space:]]' '\n' |sort | uniq -c
}

############################# usage ################################
function usage () {
  echo ""
  echo ""
  echo " Usage: $0 {build | imageload | websetup | lbsetup | control1 | control23 | worker}"
  echo ""
  echo " $0 build # Setup Build Server"
  echo " $0 imageload # Upload Images in Private Registry"
  echo " $0 lbsetup # Setup LB (HAPROXY) Server"
  echo " $0 websetup # Web (repo) Server"
  echo "-------------------------------------------------------------------------------------------------"
  echo " mkdir /opt/k8s && cd /opt/k8s && curl -#OL http://$BUILD_SERVER_IP:8080/k8s_"$KUBE_RELEASE"/k8sag.sh  && chmod 755 k8sag.sh"
  echo "-------------------------------------------------------------------------------------------------"
  echo " $0 control1 # Deploy 1st Master Server"
  echo " $0 control23 # Deploy 2nd & 3rd Master Server"
  echo " $0 worker # Deploy Worker"
  echo " $0 flask # deploy a 3 tier app"
  echo " $0 certman # deploy certmanager"
  echo " $0 ingcon # deploy ingress controller"
  echo " $0 monlog # deploy monitoring & logging"
  echo " $0 neuvector # deploy neuvector"
  echo " $0 longhorn # deploy longhorn"
  echo " $0 rancher # deploy rancher"
  echo " $0 validate # validate all the image locations"
  echo ""
  exit 1
}

case "$1" in
        build ) build;;
        imageload ) imageload;;
        lbsetup ) lbsetup;;
        websetup ) websetup;;
        control1) deploy_control1;;
        control23) deploy_control23;;
        worker) deploy_worker;;
        kubelogin) kubelogin;;
        certman) certman;;
        ingcon) ingcon;;
        monlog) monlog;;
        neuvector) neuvector;;
        longhorn) longhorn;;
        rancher) rancher;;
        flask) flask;;
        validate) validate;;
        *) usage;;
esac
