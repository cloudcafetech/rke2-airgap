#!/bin/bash

# mkdir /opt/rancher && cd /opt/rancher && curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/rke2ag.sh && chmod 755 rke2ag.sh

# interesting https://docs.k3s.io/installation/registry-mirrors

#set -ebpf

BUILD_SERVER_PUBIP=`curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//'`
BUILD_SERVER_IP=`ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1`
BUILD_SERVER_DNS=`hostname`
LB_IP=

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
# el version
export EL=$(rpm -q --queryformat '%{RELEASE}' rpm | grep -o "el[[:digit:]]")

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

# Download mount CentOS 8 ISO for CentOS
if [ ! -d /mnt/iso ]; then
  mkdir /mnt/iso
fi

if [[ ! -f CentOS-Stream-8-x86_64-latest-dvd1.iso ]]; then 
 wget http://isoredirect.centos.org/centos/8-stream/isos/x86_64/CentOS-Stream-8-x86_64-latest-dvd1.iso
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

# Download Packages for Ubuntu 20.04 
if [ ! -d /root/ubuntu-repo ]; then
  mkdir /root/ubuntu-repo
  chcon system_u:object_r:container_file_t:s0 /root/ubuntu-repo
  cd /root/ubuntu-repo/
  curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/n/nfs-utils/nfs-common_1.3.4-2.5ubuntu3_amd64.deb
  curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/libt/libtirpc/libtirpc3_1.2.5-1_amd64.deb
  curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/k/keyutils/keyutils_1.6-6ubuntu1_amd64.deb
  curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/libt/libtirpc/libtirpc-common_1.2.5-1_all.deb
  curl -#OL  http://archive.ubuntu.com/ubuntu/pool/main/n/nfs-utils/nfs-kernel-server_1.3.4-2.5ubuntu3_amd64.deb
  curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/nfs_offline_install.sh
  sed -i "s/10.182.15.216/$BUILD_SERVER_IP/g" nfs_offline_install.sh
  cd 
fi

if [[ ! -f /root/ubuntu-repo/wget_1.20.3-1ubuntu2_amd64.deb ]]; then 
 curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/ubuntu-pkg.sh && chmod 755 ubuntu-pkg.sh
 docker run --name ubuntu -it -v /root/ubuntu-repo:/host ubuntu:20.04 bash -c "$(cat ./ubuntu-pkg.sh)"
 sleep 10
 docker rm ubuntu
fi 

if [[ ! -d /var/www/html/ubuntu-repo ]]; then 
  mkdir -p /var/www/html/ubuntu-repo
  cp -vaR /root/ubuntu-repo /var/www/html/
  chcon -R -t httpd_sys_content_t /var/www/html/ubuntu-repo
  chown -R apache: /var/www/html/ubuntu-repo/
  chmod 755 /var/www/html/ubuntu-repo
fi

cp -vaR /opt/rancher/rke2_"$RKE_VERSION" /var/www/html/
cp /opt/rancher/rke2ag.sh /var/www/html/rke2_"$RKE_VERSION"/

chcon -R -t httpd_sys_content_t /var/www/html/rke2_"$RKE_VERSION"
chown -R apache: /var/www/html/rke2_"$RKE_VERSION"/
chmod 755 /var/www/html/rke2_"$RKE_VERSION"

echo "mkdir /opt/rancher && cd /opt/rancher && curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/rke2ag.sh  && chmod 755 rke2ag.sh"

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
    bind *:9345
    default_backend rke2_supervisor_backend
    mode tcp

backend rke2_supervisor_backend
    mode tcp
    balance roundrobin
    server      $MASTERDNS1 $MASTERIP1:9345 check
    server      $MASTERDNS2 $MASTERIP2:9345 check
    server      $MASTERDNS3 $MASTERIP3:9345 check

# RKE2 Kube API Server
frontend rke2_api_frontend
    bind *:6443
    default_backend rke2_api_backend
    mode tcp

backend rke2_api_backend
    mode tcp
    balance roundrobin
    server      $MASTERDNS1 $MASTERIP1:6443 check
    server      $MASTERDNS2 $MASTERIP2:6443 check
    server      $MASTERDNS3 $MASTERIP3:6443 check

# RKE2 Ingress - layer 4 tcp mode for each. Ingress Controller will handle layer 7.
frontend rke2_http_ingress_frontend
    bind :80
    default_backend rke2_http_ingress_backend
    mode http

backend rke2_http_ingress_backend
    balance roundrobin
    mode http
    server      $MASTERDNS1 $MASTERIP1:80 check
    server      $MASTERDNS2 $MASTERIP2:80 check
    server      $MASTERDNS3 $MASTERIP3:80 check

frontend rke2_https_ingress_frontend
    bind *:443
    default_backend rke2_https_ingress_backend
    mode tcp

backend rke2_https_ingress_backend
    mode tcp
    balance roundrobin
    server      $MASTERDNS1 $MASTERIP1:443 check
    server      $MASTERDNS2 $MASTERIP2:443 check
    server      $MASTERDNS3 $MASTERIP3:443 check
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
   firewall-cmd --add-port=9345/tcp --permanent
   firewall-cmd --reload 
  fi

}

################################# Image Upload ################################
function imageload () {

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
   cd /opt/rancher/helm/
   echo - get helm
   curl -#LO https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
   mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
   rm -rf linux-amd64 > /dev/null 2>&1
  fi
 
  
  echo - add repos
  cd /opt/rancher/helm/
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

  echo - Load images for Longhorn
  for i in $(cat /opt/rancher/images/longhorn/longhorn-images.txt); do
    img=$(echo $i | cut -d'/' -f2)
    pkg=$(echo $i | cut -d'/' -f1)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for CertManager
  for i in $(cat /opt/rancher/images/cert/cert-manager-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for Neuvector
  for i in $(cat /opt/rancher/images/neuvector/neuvector-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for Rancher
  for i in $(cat /opt/rancher/images/rancher/rancher-images.txt); do
    img=$(echo $i | cut -d'/' -f2)
    pkg=$(echo $i | cut -d'/' -f1)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - load images for Monitoring Logging Auth Dashboard Nginx
  for i in $(cat /opt/rancher/images/others/other-images.txt); do
    img=$(echo $i | cut -d'/' -f3)
    pkg=$(echo $i | cut -d'/' -f2)
    crane --insecure copy $i $BUILD_SERVER_IP:5000/$pkg/$img
  done

  echo - Verify Image Upload
  crane --insecure catalog $BUILD_SERVER_IP:5000

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
  
  echo - skopeo
  if ! command -v docker &> /dev/null;
  then
    echo - Installing skopeo
    yum install -y skopeo
  fi

  echo - Installing packages
  mkdir -p /root/registry/data/auth
  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   OS=Ubuntu
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

  mkdir -p /opt/rancher/{rke2_$RKE_VERSION,helm} /opt/rancher/images/{cert,rancher,longhorn,registry,flask,neuvector,others}
  cd /opt/rancher/rke2_$RKE_VERSION/

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
    tls:
      insecure_skip_verify: true
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

  echo - Get Moitoring and Logging yamls
  cd /opt/rancher/images/others/
  wget -q https://raw.githubusercontent.com/cloudcafetech/AI-for-K8S/main/kubemon.yaml
  wget -q https://github.com/cloudcafetech/kubesetup/raw/master/monitoring/dashboard/pod-monitoring.json
  wget -q https://github.com/cloudcafetech/kubesetup/raw/master/monitoring/dashboard/kube-monitoring-overview.json
  wget -q https://raw.githubusercontent.com/cloudcafetech/kubesetup/master/logging/kubelog.yaml
  wget -q https://raw.githubusercontent.com/cloudcafetech/kubesetup/master/logging/loki.yaml
  wget -q https://raw.githubusercontent.com/cloudcafetech/kubesetup/master/logging/promtail.yaml
  sed -i "s/34.125.24.130/$BUILD_SERVER_PUBIP/g" kubemon.yaml
  sed -i -e "s/quay.io/$BUILD_SERVER_IP:5000/g" -e "s/k8s.gcr.io/$BUILD_SERVER_IP:5000/g" kubemon.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" kubemon.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" kubelog.yaml
  sed -i -e "s/docker.io/$BUILD_SERVER_IP:5000/g" promtail.yaml

  echo - Get Certmanager yamls
  wget -q https://github.com/cert-manager/cert-manager/releases/download/$CERT_VERSION/cert-manager.yaml 
  sed -i -e "s/quay.io/$BUILD_SERVER_IP:5000/g" cert-manager.yaml

  echo - Setup nfs
  # share out opt directory
  echo "/opt/rancher *(ro)" > /etc/exports
  echo "/root/ubuntu-repo *(ro)" >> /etc/exports
  systemctl enable nfs-server.service && systemctl start nfs-server.service

  #imageupload
  #websetup
  #lbsetup
  #compressall

}

################################# base ################################
function base () {
# install all the base bits.

  # Download from Build server
  if [ ! -d /opt/rancher ]; then
   mkdir /opt/rancher
  fi

  #mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  if [ ! -d "/opt/rancher/rke2_$RKE_VERSION" ]; then
     mkdir "/opt/rancher/rke2_$RKE_VERSION"
  fi

  cd "/opt/rancher/rke2_$RKE_VERSION"
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/rke2-images.linux-amd64.tar.zst
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/rke2.linux-amd64.tar.gz
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/sha256sum-amd64.txt
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/rke2-common-$RKE_VERSION.rke2r1-0."$EL".x86_64.rpm
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/registries.yaml
  curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/install.sh

  ## For Debian distribution
  if [[ -n $(uname -a | grep -iE 'ubuntu|debian') ]]; then 
   curl -#OL http://$BUILD_SERVER_IP:8080/ubuntu-repo/nfs_offline_install.sh && chmod 755 nfs_offline_install.sh
   ./nfs_offline_install.sh
   sleep 10
   if [ -z "$(ls -A /mnt/pkg)" ]; then
     mkdir /mnt/pkg
     mount $BUILD_SERVER_IP:/root/ubuntu-repo /mnt/pkg
     cd /mnt/pkg && dpkg -i *.deb
   fi 
   #echo "# Local APT Repository" >> /etc/apt/sources.list 
   #echo "deb [trusted=yes] http://$BUILD_SERVER_IP:8080/ubuntu-repo ./" >> /etc/apt/sources.list
   #apt update -y
   #apt install apt-transport-https ca-certificates gpg nfs-common curl wget git net-tools unzip jq zip nmap telnet dos2unix apparmor ldap-utils nfs-kernel-server -y
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
   curl -OL http://$BUILD_SERVER_IP:8080/iso/centos8-remote.repo
   rm -rf /etc/yum.repos.d/* 
   cp centos8-remote.repo /etc/yum.repos.d/centos8.repo
   chmod 644 /etc/yum.repos.d/centos8.repo
   yum install -y git curl wget bind-utils jq httpd-tools zip unzip nfs-utils go nmap telnet dos2unix zstd container-selinux libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils iptables skopeo
   #yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
   #systemctl enable --now iscsid
   #echo -e "[keyfile]\nunmanaged-devices=interface-name:cali*;interface-name:flannel*" > /etc/NetworkManager/conf.d/rke2-canal.conf
  fi

}

################################# Deploy Master 1 ################################
function deploy_control1 () {
  # this is for the first node

  base

  # Setting up Kubernetes Master using RKE2
  if [ ! -d  /etc/rancher/rke2 ]; then
     mkdir -p /etc/rancher/rke2/  
  fi
  if [ ! -d  /var/lib/rancher/rke2/server/manifests ]; then
     mkdir -p /var/lib/rancher/rke2/server/manifests/  
  fi
  if [ ! -d  /var/lib/rancher/rke2/agent/images ]; then
     mkdir -p /var/lib/rancher/rke2/agent/images 
  fi
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
  - rke2-snapshot-controller
  - rke2-snapshot-controller-crd
  - rke2-snapshot-validation-webhook
#  - rke2-ingress-nginx
#  - rke2-coredns
#  - rke2-metrics-server
#node-taint:
  #- "CriticalAddonsOnly=true:NoExecute"
EOF

  echo - Install rke2
  cd /opt/rancher/rke2_$RKE_VERSION
  chmod 755 ./install.sh

 # insall rke2 - stig'd
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  #yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
  systemctl enable --now rke2-server.service

  sleep 30

  mkdir ~/.kube
  ln -s /etc/rancher/rke2/rke2.yaml ~/.kube/config  
  chmod 600 /root/.kube/config
  ln -s /var/lib/rancher/rke2/agent/etc/crictl.yaml /etc/crictl.yaml
  export PATH=/var/lib/rancher/rke2/bin:$PATH
  echo "export PATH=/var/lib/rancher/rke2/bin:$PATH" >> $HOME/.bash_profile
  echo "alias oc=/var/lib/rancher/rke2/bin/kubectl" >> $HOME/.bash_profile

  # wait and add link
  #echo "export KUBECONFIG=/etc/rancher/rke2/rke2.yaml CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml PATH=$PATH:/var/lib/rancher/rke2/bin" >> ~/.bashrc
  #ln -s /var/run/k3s/containerd/containerd.sock /var/run/containerd/containerd.sock
  #source ~/.bashrc

  sleep 5

  echo - unpack helm
  mkdir /mnt/test
  mount $BUILD_SERVER_IP:/opt/rancher /mnt/test
  cp /mnt/test/helm/helm-v3.13.2-linux-amd64.tar.gz .
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1

  source ~/.bashrc

}

################################# Deploy Master 2 & 3 ################################
function deploy_control23 () {
  # this is for the 2nd & 3rd Master node

  base

  # Setting up Kubernetes Master using RKE2
  if [ ! -d  /etc/rancher/rke2 ]; then
     mkdir -p /etc/rancher/rke2/  
  fi
  if [ ! -d  /var/lib/rancher/rke2/server/manifests ]; then
     mkdir -p /var/lib/rancher/rke2/server/manifests/  
  fi
  if [ ! -d  /var/lib/rancher/rke2/agent/images ]; then
     mkdir -p /var/lib/rancher/rke2/agent/images 
  fi
  cp /opt/rancher/rke2_$RKE_VERSION/registries.yaml /etc/rancher/rke2/registries.yaml

cat << EOF >  /etc/rancher/rke2/config.yaml
server: https://$MASTERIP1:9345
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

  mkdir ~/.kube
  ln -s /etc/rancher/rke2/rke2.yaml ~/.kube/config  
  chmod 600 /root/.kube/config
  ln -s /var/lib/rancher/rke2/agent/etc/crictl.yaml /etc/crictl.yaml
  export PATH=/var/lib/rancher/rke2/bin:$PATH
  echo "export PATH=/var/lib/rancher/rke2/bin:$PATH" >> $HOME/.bash_profile
  echo "alias oc=/var/lib/rancher/rke2/bin/kubectl" >> $HOME/.bash_profile

  # wait and add link
  #echo "export KUBECONFIG=/etc/rancher/rke2/rke2.yaml CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml PATH=$PATH:/var/lib/rancher/rke2/bin" >> ~/.bashrc
  #ln -s /var/run/k3s/containerd/containerd.sock /var/run/containerd/containerd.sock
  #source ~/.bashrc

  sleep 5

  echo - unpack helm
  mkdir /mnt/test
  mount $BUILD_SERVER_IP:/opt/rancher /mnt/test
  cp /mnt/test/helm/helm-v3.13.2-linux-amd64.tar.gz .
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1

  source ~/.bashrc

  echo "------------------------------------------------------------------"

}

################################# deploy worker ################################
function deploy_worker () {
  echo - deploy worker

  base

  # Setting up Kubernetes Master using RKE2
  if [ ! -d  /etc/rancher/rke2 ]; then
     mkdir -p /etc/rancher/rke2/  
  fi
  if [ ! -d  /var/lib/rancher/rke2/server/manifests ]; then
     mkdir -p /var/lib/rancher/rke2/server/manifests/  
  fi
  if [ ! -d  /var/lib/rancher/rke2/agent/images ]; then
     mkdir -p /var/lib/rancher/rke2/agent/images 
  fi
  cp /opt/rancher/rke2_$RKE_VERSION/registries.yaml /etc/rancher/rke2/registries.yaml

cat << EOF >  /etc/rancher/rke2/config.yaml
server: https://$LB_IP:9345
token: pkls-secret
node-label:
- "region=worker"
EOF

  # install rke2
  cd /opt/rancher
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" INSTALL_RKE2_TYPE=agent sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  systemctl enable --now rke2-agent.service

  # wait and add link
  ln -s /var/lib/rancher/rke2/agent/etc/crictl.yaml /etc/crictl.yaml
  export PATH=/var/lib/rancher/rke2/bin:$PATH
  echo "export PATH=/var/lib/rancher/rke2/bin:$PATH" >> $HOME/.bash_profile

}

################## Cluster login from Build Server #####################
function kubelogin () {
 echo - Kubernetes login setup
 #scp -i <PEM file location> <USER>@<MASTER1>:/etc/rancher/rke2/rke2.yaml .
 cp rke2.yaml kubeconfig
 sed -i "s/127.0.0.1/$LB_IP/g" kubeconfig
 export KUBECONFIG=./kubeconfig
 kubectl get no

}

################################# flask ################################
function flask () {
  # dummy 3 tier app - asked for by a customer. 
  echo - load images
  for file in $(ls /opt/rancher/images/flask/ | grep -v yaml ); do 
     skopeo copy docker-archive:/opt/rancher/images/flask/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk '{print "$BUILD_SERVER_IP:5000/flask/"$1}')" --dest-tls-verify=false
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
  cd /opt/rancher/images/others/
  echo - Cert Manager Setup
  kubectl create -f cert-manager.yaml
}

###################### Monitoring And Logging #############################
function monlog () {
  # deploy Monitoring & Logging with private registry images
  cd /opt/rancher/images/others/
  echo - Kubernetes Monitoring Setup
  kubectl create ns monitoring
  kubectl create configmap grafana-dashboards -n monitoring --from-file=pod-monitoring.json --from-file=kube-monitoring-overview.json
  kubectl create -f kubemon.yaml -n monitoring

  echo - Kubernetes Logging Setup
  kubectl create ns logging
  kubectl create secret generic loki -n logging --from-file=loki.yaml
  kubectl create -f kubelog.yaml -n logging
  kubectl delete ds loki-fluent-bit-loki -n logging
  kubectl create -f promtail.yaml -n logging
}

################################# longhorn ################################
function longhorn () {
  # deploy longhorn with private registry images
  echo - deploying longhorn
  helm upgrade -i longhorn /opt/rancher/helm/longhorn-$LONGHORN_VERSION.tgz --namespace longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.$DOMAIN --set global.cattle.systemDefaultRegistry=$BUILD_SERVER_IP:5000
}

################################# neuvector ################################
function neuvector () {
  # deploy neuvector with private registry images
  echo - deploying neuvector
  helm upgrade -i neuvector --namespace neuvector /opt/rancher/helm/core-$NEU_VERSION.tgz --create-namespace  --set imagePullSecrets=regsecret --set k3s.enabled=true --set k3s.runtimePath=/run/k3s/containerd/containerd.sock  --set manager.ingress.enabled=true --set controller.pvc.enabled=true --set manager.svc.type=ClusterIP --set controller.pvc.capacity=500Mi --set registry=$BUILD_SERVER_IP:5000 --set controller.image.repository=neuvector/controller --set enforcer.image.repository=neuvector/enforcer --set manager.image.repository=neuvector/manager --set cve.updater.image.repository=neuvector/updater --set manager.ingress.host=neuvector.$DOMAIN --set internal.certmanager.enabled=true
}

################################# rancher ################################
function rancher () {
  # deploy rancher with local helm/images
  echo - deploying rancher
  helm upgrade -i cert-manager /opt/rancher/helm/cert-manager-$CERT_VERSION.tgz --namespace cert-manager --create-namespace --set installCRDs=true --set image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-controller --set webhook.image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-webhook --set cainjector.image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-cainjector --set startupapicheck.image.repository=$BUILD_SERVER_IP:5000/cert/cert-manager-ctl 

  helm upgrade -i rancher /opt/rancher/helm/rancher-$RANCHER_VERSION.tgz --namespace cattle-system --create-namespace --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set useBundledSystemChart=true --set rancherImage=$BUILD_SERVER_IP:5000/rancher/rancher --set systemDefaultRegistry=$BUILD_SERVER_IP:5000 --set hostname=rancher.$DOMAIN

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
  echo " mkdir /opt/rancher && cd /opt/rancher && curl -#OL http://$BUILD_SERVER_IP:8080/rke2_"$RKE_VERSION"/rke2ag.sh  && chmod 755 rke2ag.sh"
  echo "-------------------------------------------------------------------------------------------------"
  echo " $0 control1 # Deploy 1st Master Server"
  echo " $0 control23 # Deploy 2nd & 3rd Master Server"
  echo " $0 worker # Deploy Worker"
  echo " $0 flask # deploy a 3 tier app"
  echo " $0 certman # deploy certmanager"
  echo " $0 monlog # deploy monitoring & logging"
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
        kubelogin) kubelogin;;
        certman) certman;;
        monlog) monlog;;
        neuvector) neuvector;;
        longhorn) longhorn;;
        rancher) rancher;;
        flask) flask;;
        validate) validate;;
        compressall) compressall;;
        *) usage;;
esac
