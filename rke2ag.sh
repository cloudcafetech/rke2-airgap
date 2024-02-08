#!/bin/bash

# mkdir /opt/rancher && cd /opt/rancher && curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/rke2ag.sh && chmod 755 rke2ag.sh

# interesting https://docs.k3s.io/installation/registry-mirrors

set -ebpf

BUILD_SERVER_IP=`ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1`
LB_IP=

MASTERDNS1=
MASTERDNS2=
MASTERDNS3=

MASTERIP1=
MASTERIP2=
MASTERIP3=

INFRAIP1=
INFRAIP2=

INFRADNS1=
INFRANDS2=


# versions
export RKE_VERSION=1.26.12
export CERT_VERSION=v1.13.3
export RANCHER_VERSION=2.8.1
export LONGHORN_VERSION=1.5.3
export NEU_VERSION=2.6.6
export DOMAIN=awesome.sauce

######  NO MOAR EDITS #######
export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'

export PATH=$PATH:/usr/local/bin

########################## Webserver Setup ################################
websetup() {

echo - Apache Web Server
yum install -y httpd
sed -i 's/Listen 80/Listen 0.0.0.0:8080/' /etc/httpd/conf/httpd.conf
setsebool -P httpd_read_user_content 1
systemctl start httpd;systemctl enable httpd
#firewall-cmd --add-port=8080/tcp --permanent
#firewall-cmd --reload

# Download mount CentOS 8 ISO for CentOS 8 server
mkdir /mnt/iso
wget http://isoredirect.centos.org/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso
mount -t iso9660 -o ro,loop CentOS-Stream-8-x86_64-latest-dvd1.iso /mnt/iso
cd /mnt/iso

mkdir /opt/iso_files
cp -va * /opt/iso_files/
mkdir -p /var/www/html/
cp -vaR /opt/iso_files /var/www/html/
chcon -R -t httpd_sys_content_t /var/www/html/iso_files
chown -R apache: /var/www/html/iso_files/
chmod 755 /var/www/html/iso_files

cat <<EOF > /var/www/html/iso_files/centos8-remote.repo
[centos8_Appstream_remote]
baseurl=http://$BUILD_SERVER_IP:8080/iso_files/AppStream
gpgcheck=0
name=CentOS Linux App_stream remote
enable=1

[centos8_BaseOS_remote]
baseurl=http://$BUILD_SERVER_IP:8080/iso_files/BaseOS
gpgcheck=0
name=CentOS Linux BaseOS remote
enable=1
EOF

echo "curl -OL http://$BUILD_SERVER_IP:8080/iso_files/centos8-remote.repo"
echo "cp centos8-remote.repo /etc/yum.repos.d/centos8.repo"
echo "chmod 644 /etc/yum.repos.d/centos8.repo"

echo "mkdir /root/old-repo"
echo "mv /etc/yum.repos.d/C* /root/old-repo/"
echo "mv /etc/yum.repos.d/google-cloud.repo /root/old-repo/"

echo "curl $BUILD_SERVER_IP:8080/iso_files/"

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

# RKE2 Supervisor Server
frontend rke2_supervisor_frontend
    bind :6443
    default_backend rke2_supervisor_backend
    mode tcp

backend rke2_supervisor_backend
    mode tcp
    balance source
    server      $MASTERDNS1 $MASTERIP1:9345 check
    server      $MASTERDNS2 $MASTERIP2:9345 check
    server      $MASTERDNS3 $MASTERIP3:9345 check

# RKE2 Kube API Server
frontend rke2_api_frontend
    bind :6443
    default_backend rke2_api_backend
    mode tcp

backend rke2_api_backend
    mode tcp
    balance source
    server      $MASTERDNS1 $MASTERIP1:6443 check
    server      $MASTERDNS2 $MASTERIP2:6443 check
    server      $MASTERDNS3 $MASTERIP3:6443 check

# RKE2 Ingress - layer 4 tcp mode for each. Ingress Controller will handle layer 7.
frontend rke2_http_ingress_frontend
    bind :80
    default_backend rke2_http_ingress_backend
    mode tcp

backend rke2_http_ingress_backend
    balance source
    mode tcp
    server      $INFRADNS1 $INFRAIP1:80 check
    server      $INFRADNS2 $INFRAIP2:80 check

frontend rke2_https_ingress_frontend
    bind *:443
    default_backend rke2_https_ingress_backend
    mode tcp

backend rke2_https_ingress_backend
    mode tcp
    balance source
    server      $INFRADNS1 $INFRAIP1:443 check
    server      $INFRADNS2 $INFRAIP2:443 check
EOF

  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   systemctl start haproxy;systemctl enable haproxy
  else
   setsebool -P haproxy_connect_any 1
   systemctl start haproxy;systemctl enable haproxy
   firewall-cmd --add-port=6443/tcp --permanent
   firewall-cmd --add-port=443/tcp --permanent
   firewall-cmd --add-service=http --permanent
   firewall-cmd --add-service=https --permanent
   firewall-cmd --add-port=9000/tcp --permanent
   firewall-cmd --reload 
  fi

}

################################# Image Upload ################################
function imageload () {

  echo - "Check & Install docker, crane & setup docker Private Registry"
  if ! command -v docker &> /dev/null;
  then
    echo "Trying to Install Docker..."
    curl -s https://releases.rancher.com/install-docker/19.03.sh | sh
    systemctl start docker; systemctl enable docker
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
    docker run -itd -p 5000:5000 --restart=always --name private-registry -v /root/registry/data/auth:/auth -v /root/registry/data:/var/lib/registry \
    -e "REGISTRY_AUTH=htpasswd" \
    -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
    -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    registry
  fi

  echo - Checking helm 
  if ! command -v helm &> /dev/null;
  then
   echo - Get Helm Charts
   cd /opt/rancher/helm/
   echo - get helm
   curl -#LO https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
   rm -rf linux-amd64 > /dev/null 2>&1
  fi

  echo - add repos
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
  mkdir -p /opt/rancher/{rke2_$RKE_VERSION,helm} /opt/rancher/images/{cert,rancher,longhorn,registry,flask,neuvector,others}

  echo - create image dir
  cd /opt/rancher/images/

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
  helm template /opt/rancher/helm/cert-manager-$CERT_VERSION.tgz | awk '$1 ~ /image:/ {print $2}' | sed s/\"//g > cert/cert-manager-images.txt

  echo - longhorn image list
  curl -#L https://raw.githubusercontent.com/longhorn/longhorn/v$LONGHORN_VERSION/deploy/longhorn-images.txt -o longhorn/longhorn-images.txt

  echo - neuvector image list
  helm template /opt/rancher/helm/core-$NEU_VERSION.tgz | awk '$1 ~ /image:/ {print $2}' | sed -e 's/\"//g' > neuvector/neuvector-images.txt

  echo - other image list
  curl -#L https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/other-images.txt -o others/other-images.txt

  echo - Login docker for upload images
  docker login -u admin -p admin@2675 localhost:5000

  echo - Load images for Mongo Redis Registry
  crane copy mongo:latest localhost:5000/mongo:latest
  crane copy redis:latest localhost:5000/redis:latest
  crane copy registry:latest localhost:5000/registry:latest
  crane copy debian:9 localhost:5000/debian:9
  crane copy k8s.gcr.io/addon-resizer:1.7 localhost:5000/addon-resizer:1.7
  crane copy prom/alertmanager:v0.16.2 localhost:5000/prometheus/alertmanager:v0.16.0

  echo - Load images for Longhorn
  for i in $(cat /opt/rancher/images/longhorn/longhorn-images.txt); do
    img=$(echo $i | cut -d'/' -f2)
    pkg=$(echo $i | cut -d'/' -f1)
    crane copy $i localhost:5000/$pkg/$img
  done

  echo - load images for CertManager
  for i in $(cat /opt/rancher/images/cert/cert-manager-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane copy $i localhost:5000/$pkg/$img
  done

  echo - load images for Neuvector
  for i in $(cat /opt/rancher/images/neuvector/neuvector-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane copy $i localhost:5000/$pkg/$img
  done

  echo - load images for Rancher
  for i in $(cat /opt/rancher/images/rancher/rancher-images.txt); do
    img=$(echo $i | cut -d'/' -f2)
    pkg=$(echo $i | cut -d'/' -f1)
    crane copy $i localhost:5000/$pkg/$img
  done

  echo - load images for Monitoring Logging Auth Dashboard Nginx
  for i in $(cat /opt/rancher/images/others/other-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane copy $i localhost:5000/$pkg/$img
  done

  # Verify Image upload
  crane catalog localhost:5000

}

################################# Compress All ################################
function compressall () {

  cd /opt/rancher/
  echo - compress all the things
  if ! test -f /opt/rke2_rancher_longhorn.zst; then
   tar -I zstd -vcf /opt/rke2_rancher_longhorn.zst $(ls) > /dev/null 2>&1
  fi

  # look at adding encryption - https://medium.com/@lumjjb/encrypting-container-images-with-skopeo-f733afb1aed4  

  echo "------------------------------------------------------------------"
  echo " to uncompress : "
  echo "   yum install -y zstd"
  echo "   mkdir /opt/rancher"
  echo "   tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher"
  echo "------------------------------------------------------------------"

}

################################# build ################################
function build () {
  
  echo - Installing packages
  mkdir -p /root/registry/data/auth
  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   OS=Ubuntu
   apt install -y apt-transport-https ca-certificates gpg nfs-common curl wget git net-tools unzip jq zip nmap telnet dos2unix ldap-utils haproxy apparmor 
  else
   # el version
   export EL=$(rpm -q --queryformat '%{RELEASE}' rpm | grep -o "el[[:digit:]]")
   chcon system_u:object_r:container_file_t:s0 /root/registry/data
   yum install -y git curl wget openldap openldap-clients bind-utils jq httpd-tools haproxy zip unzip go nmap telnet dos2unix zstd nfs-utils iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils skopeo
  fi

  echo - "Install docker, crane & setup docker private registry"
  if ! command -v docker &> /dev/null;
  then
    echo "Trying to Install Docker..."
    #dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    #dnf install docker-ce --nobest --allowerasing -y
    curl -s https://releases.rancher.com/install-docker/19.03.sh | sh
  fi 
  systemctl start docker; systemctl enable docker

  if ! command -v crane &> /dev/null;
  then
    echo "Trying to Install Crane..."
    curl -sL "https://github.com/google/go-containerregistry/releases/download/v0.19.0/go-containerregistry_Linux_x86_64.tar.gz" > go-containerregistry.tar.gz
    tar -zxvf go-containerregistry.tar.gz -C /usr/local/bin/ crane
  fi 

  mkdir -p /opt/rancher/{rke2_$RKE_VERSION,helm} /opt/rancher/images/{cert,rancher,longhorn,registry,flask,neuvector,others}
  cd /opt/rancher/rke2_$RKE_VERSION/

  echo - Private Registry Setup
  if ! test -f /root/registry/data/auth/htpasswd; then
    docker run --name htpass --entrypoint htpasswd httpd:2 -Bbn admin admin@2675 > /root/registry/data/auth/htpasswd  
    docker rm htpass
  fi

  PR=`docker ps -a -q -f name=private-registry`
  if [[ $PR == "" ]]; then
    docker run -itd -p 5000:5000 --restart=always --name private-registry -v /root/registry/data/auth:/auth -v /root/registry/data:/var/lib/registry \
    -e "REGISTRY_AUTH=htpasswd" \
    -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
    -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    registry
  fi

cat <<EOF > /opt/rancher/rke2_$RKE_VERSION/registries.yaml
mirrors:
  docker.io:
    endpoint:
      - "http://$BUILD_SERVER_IP:5000"
configs:
  "$BUILD_SERVER_IP:5000":
    auth:
      username: admin
      password: admin@2675
    #tls:
      #insecure_skip_verify: true
EOF

  echo - download rke, rancher and longhorn
  # from https://docs.rke2.io/install/airgap
  curl -#OL https://github.com/rancher/rke2/releases/download/v$RKE_VERSION%2Brke2r1/rke2-images.linux-amd64.tar.zst
  curl -#OL https://github.com/rancher/rke2/releases/download/v$RKE_VERSION%2Brke2r1/rke2.linux-amd64.tar.gz
  curl -#OL https://github.com/rancher/rke2/releases/download/v$RKE_VERSION%2Brke2r1/sha256sum-amd64.txt
  curl -#OL https://github.com/rancher/rke2-packaging/releases/download/v$RKE_VERSION%2Brke2r1.stable.0/rke2-common-$RKE_VERSION.rke2r1-0."$EL".x86_64.rpm
  curl -#OL https://github.com/rancher/rke2-selinux/releases/download/v0.17.stable.1/rke2-selinux-0.17-1."$EL".noarch.rpm

  echo - get the install script
  curl -sfL https://get.rke2.io -o install.sh

  echo - Checking helm 
  if ! command -v helm &> /dev/null;
  then
   echo - Get Helm Charts
   cd /opt/rancher/helm/
   echo - get helm
   curl -#LO https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
   rm -rf linux-amd64 > /dev/null 2>&1
  fi

  echo - Setup nfs
  # share out opt directory
  echo "/opt/rancher *(ro)" > /etc/exports
  systemctl enable nfs-server.service && systemctl start nfs-server.service

  #imageupload
  #lbsetup
  #compressall

}

################################# base ################################
function base () {
# install all the base bits.

### For Debian distribution
if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
 apt update -y
 apt install apt-transport-https ca-certificates gpg nfs-common curl wget git net-tools unzip jq zip nmap telnet dos2unix apparmor ldap-utils -y
 # Stopping and disabling firewalld by running the commands on all servers
 systemctl stop ufw
 systemctl stop apparmor.service
 systemctl disable --now ufw
 systemctl disable --now apparmor.service 
### For Redhat distribution
else
 # Stopping and disabling firewalld & SELinux
 systemctl stop firewalld; systemctl disable firewalld
 setenforce 0
 sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
 yum install -y git curl wget bind-utils jq httpd-tools zip unzip nfs-utils go nmap telnet dos2unix zstd container-selinux libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils iptables skopeo
 yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
 #systemctl enable --now iscsid
 #echo -e "[keyfile]\nunmanaged-devices=interface-name:cali*;interface-name:flannel*" > /etc/NetworkManager/conf.d/rke2-canal.conf
fi

}

################################# Deploy Master 1 ################################
function deploy_control1 () {
  # this is for the first node
  # mkdir /opt/rancher
  # tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher

  # Mount from Build server
  mkdir /opt/rancher
  mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  base

  # Setting up Kubernetes Master using RKE2
  mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/ /var/lib/rancher/rke2/agent/images 
  cp /opt/rancher/rke2_$RKE_VERSION/registries.yaml /etc/rancher/rke2/registries.yaml

cat << EOF >  /etc/rancher/rke2/config.yaml
token: pkls-secret
write-kubeconfig-mode: "0644"
cluster-cidr: 192.168.0.0/16
service-cidr: 192.167.0.0/16
node-label:
- "region=master"
tls-san:
  - "$LB_IP"
  - "$MASTERDNS1"
  - "$MASTERDNS2"
  - "$MASTERDNS3"
  - "$MASTERIP1"
  - "$MASTERIP2"
  - "$MASTERIP3"
disable:
  - rke2-ingress-nginx
  - rke2-snapshot-controller
  - rke2-snapshot-controller-crd
  - rke2-snapshot-validation-webhook
#  - rke2-coredns
#  - rke2-metrics-server
#node-taint:
  #- "CriticalAddonsOnly=true:NoExecute"
EOF

  echo - Install rke2
  cd /opt/rancher/rke2_$RKE_VERSION

 # insall rke2 - stig'd
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  #yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
  systemctl enable --now rke2-server.service

  sleep 30

  # wait and add link
  echo "export KUBECONFIG=/etc/rancher/rke2/rke2.yaml CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml PATH=$PATH:/var/lib/rancher/rke2/bin" >> ~/.bashrc
  ln -s /var/run/k3s/containerd/containerd.sock /var/run/containerd/containerd.sock
  source ~/.bashrc

  sleep 5

  echo - unpack helm
  cd /opt/rancher/helm
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1

  #cat /var/lib/rancher/rke2/server/token > /opt/rancher/token

  source ~/.bashrc

  echo "------------------------------------------------------------------"
  echo " Next:"
  echo "  - Mkdir: \"mkdir /opt/rancher\""
  echo "  - Mount: \"mount $(hostname -I | awk '{ print $1 }'):/opt/rancher /opt/rancher\""
  echo "  - CD: \"cd /opt/rancher\""
  echo "  - Run: \""$0" worker\" on your worker nodes"
  echo "------------------------------------------------------------------"
  echo "  - yolo: \"mkdir /opt/rancher && echo \"$(hostname -I | awk '{ print $1 }'):/opt/rancher /opt/rancher nfs rw,hard,rsize=1048576,wsize=1048576 0 0\" >> /etc/fstab && mount -a && cd /opt/rancher && $0 worker\""
  echo "------------------------------------------------------------------"

}

################################# Deploy Master 2 & 3 ################################
function deploy_control23 () {
  # this is for the 2nd & 3rd Master node
  # mkdir /opt/rancher
  # tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher

  # Mount from Build server
  mkdir /opt/rancher
  mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  base

  # Setting up Kubernetes Master using RKE2
  mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/ /var/lib/rancher/rke2/agent/images 
  cp /opt/rancher/rke2_$RKE_VERSION/registries.yaml /etc/rancher/rke2/registries.yaml

cat << EOF >  /etc/rancher/rke2/config.yaml
server: https://MASTERIP1:9345
token: pkls-secret
write-kubeconfig-mode: "0644"
node-label:
- "region=master"
tls-san:
  - "$LB_IP"
  - "$MASTERDNS1"
  - "$MASTERDNS2"
  - "$MASTERDNS3"
  - "$MASTERIP1"
  - "$MASTERIP2"
  - "$MASTERIP3"
#node-taint:
  #- "CriticalAddonsOnly=true:NoExecute"
EOF

  echo - Install rke2
  cd /opt/rancher/rke2_$RKE_VERSION

 # insall rke2 - stig'd
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  #yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
  systemctl enable --now rke2-server.service

  sleep 30

  # wait and add link
  echo "export KUBECONFIG=/etc/rancher/rke2/rke2.yaml CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml PATH=$PATH:/var/lib/rancher/rke2/bin" >> ~/.bashrc
  ln -s /var/run/k3s/containerd/containerd.sock /var/run/containerd/containerd.sock
  source ~/.bashrc

  sleep 5

  echo - unpack helm
  cd /opt/rancher/helm
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1

  source ~/.bashrc

  echo "------------------------------------------------------------------"

}

################################# deploy worker ################################
function deploy_worker () {
  echo - deploy worker

  # Mount from Build server
  mkdir /opt/rancher
  mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  base

  # Setting up Kubernetes Master using RKE2
  mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/ /var/lib/rancher/rke2/agent/images 
  cp /opt/rancher/rke2_$RKE_VERSION/registries.yaml /etc/rancher/rke2/registries.yaml

cat << EOF >  /etc/rancher/rke2/config.yaml
server: https://MASTERIP1:9345
token: pkls-secret
node-label:
- "region=worker"
EOF

  # setup RKE2
  mkdir -p /etc/rancher/rke2/

  # install rke2
  cd /opt/rancher
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" INSTALL_RKE2_TYPE=agent sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  #yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
  systemctl enable --now rke2-agent.service

}

################################# flask ################################
function flask () {
  # dummy 3 tier app - asked for by a customer. 
  echo - load images
  for file in $(ls /opt/rancher/images/flask/ | grep -v yaml ); do 
     skopeo copy docker-archive:/opt/rancher/images/flask/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk '{print "localhost:5000/flask/"$1}')" --dest-tls-verify=false
  done

  echo "------------------------------------------------------------------"
  echo " to deploy: "
  echo "   edit /opt/rancher/images/flask/flask.yaml to the ingress URL."
  echo "   kubectl apply -f /opt/rancher/images/flask/flask.yaml"
  echo "------------------------------------------------------------------"

}

################################# longhorn ################################
function longhorn () {
  # deploy longhorn with local helm/images
  echo - deploying longhorn
  helm upgrade -i longhorn /opt/rancher/helm/longhorn-$LONGHORN_VERSION.tgz --namespace longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.$DOMAIN --set global.cattle.systemDefaultRegistry=localhost:5000
}

################################# neuvector ################################
function neuvector () {
  # deploy neuvector with local helm/images
  echo - deploying neuvector
  helm upgrade -i neuvector --namespace neuvector /opt/rancher/helm/core-$NEU_VERSION.tgz --create-namespace  --set imagePullSecrets=regsecret --set k3s.enabled=true --set k3s.runtimePath=/run/k3s/containerd/containerd.sock  --set manager.ingress.enabled=true --set controller.pvc.enabled=true --set manager.svc.type=ClusterIP --set controller.pvc.capacity=500Mi --set registry=localhost:5000 --set controller.image.repository=neuvector/controller --set enforcer.image.repository=neuvector/enforcer --set manager.image.repository=neuvector/manager --set cve.updater.image.repository=neuvector/updater --set manager.ingress.host=neuvector.$DOMAIN --set internal.certmanager.enabled=true
}

################################# rancher ################################
function rancher () {
  # deploy rancher with local helm/images
  echo - deploying rancher
  helm upgrade -i cert-manager /opt/rancher/helm/cert-manager-$CERT_VERSION.tgz --namespace cert-manager --create-namespace --set installCRDs=true --set image.repository=localhost:5000/cert/cert-manager-controller --set webhook.image.repository=localhost:5000/cert/cert-manager-webhook --set cainjector.image.repository=localhost:5000/cert/cert-manager-cainjector --set startupapicheck.image.repository=localhost:5000/cert/cert-manager-ctl 

  helm upgrade -i rancher /opt/rancher/helm/rancher-$RANCHER_VERSION.tgz --namespace cattle-system --create-namespace --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set useBundledSystemChart=true --set rancherImage=localhost:5000/rancher/rancher --set systemDefaultRegistry=localhost:5000 --set hostname=rancher.$DOMAIN

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
  echo "-------------------------------------------------"
  echo ""
  echo " Usage: $0 {build | imageload | lbsetup | control1 | control23 | worker}"
  echo ""
  echo " $0 build # Setup Build Server"
  echo " $0 imageload # Upload Images in Private Registry"
  echo " $0 lbsetup # Setup LB (HAPROXY) Server"
  echo " $0 websetup # Web (repo) Server"
  echo " $0 control1 # Deploy 1st Master Server"
  echo " $0 control23 # Deploy 2nd & 3rd Master Server"
  echo " $0 worker # Deploy Worker"
  echo " $0 flask # deploy a 3 tier app"
  echo " $0 neuvector # deploy neuvector"
  echo " $0 longhorn # deploy longhorn"
  echo " $0 rancher # deploy rancher"
  echo " $0 validate # validate all the image locations"
  echo " $0 compressall # Compress all data"
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
        neuvector) neuvector;;
        longhorn) longhorn;;
        rancher) rancher;;
        flask) flask;;
        validate) validate;;
        compressall) compressall;;
        *) usage;;
esac
