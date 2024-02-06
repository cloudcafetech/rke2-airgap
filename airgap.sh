#!/bin/bash

# mkdir /opt/rancher && cd /opt/rancher && curl -#OL https://raw.githubusercontent.com/cloudcafetech/rke2-airgap/main/airgap.sh && chmod 755 airgap.sh

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

# el version
export EL=$(rpm -q --queryformat '%{RELEASE}' rpm | grep -o "el[[:digit:]]")

# Better error checking
echo -e "checking skopeo "
command -v skopeo >/dev/null 2>&1 || { echo -e -n "$RED" " ** skopeo was not found ** ""$NO_COLOR"; yum install -y skopeo > /dev/null 2>&1; }
echo -e "- installed ""$GREEN""ok" "$NO_COLOR"

################################# build ################################
function build () {
  
  echo - Installing packages
  yum install -y git curl wget openldap openldap-clients bind-utils jq httpd-tools zip unzip go nmap telnet dos2unix zstd nfs-utils iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils

  echo - "Install docker, crane & setup docker private registry"
  if ! command -v docker &> /dev/null;
  then
    echo "Trying to Install Docker..."
    dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    dnf install docker-ce --nobest --allowerasing -y
    #curl -s https://releases.rancher.com/install-docker/19.03.sh | sh
  fi 
  systemctl start docker; systemctl enable docker

  curl -sL "https://github.com/google/go-containerregistry/releases/download/v0.19.0/go-containerregistry_Linux_x86_64.tar.gz" > go-containerregistry.tar.gz
  tar -zxvf go-containerregistry.tar.gz -C /usr/local/bin/ crane

  mkdir -p /opt/rancher/{rke2_$RKE_VERSION,helm} /opt/rancher/images/{cert,rancher,longhorn,registry,flask,neuvector}
  cd /opt/rancher/rke2_$RKE_VERSION/

  echo - Private Registry Setup
  mkdir -p /root/registry/data/auth
  chcon system_u:object_r:container_file_t:s0 /root/registry/data

  if ! test -f /root/registry/data/auth/htpasswd; then
    docker run --name htpass --entrypoint htpasswd httpd:2 -Bbn admin admin@2675 > /root/registry/data/auth/htpasswd  
    docker rm htpass
  fi

  PR=`docker ps -a -q -f name=private-registry`
  if [ $PR == " " ]; then
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

  echo - Get Helm Charts
  cd /opt/rancher/helm/

  echo - get helm
  curl -#LO https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  tar -zxvf helm-v3.13.2-linux-amd64.tar.gz > /dev/null 2>&1
  mv linux-amd64/helm /usr/local/bin/ > /dev/null 2>&1
  rm -rf linux-amd64 > /dev/null 2>&1

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

 # get images
  echo - skopeo - cert-manager
  for i in $(cat cert/cert-manager-images.txt); do 
    skopeo inspect docker-archive:cert/"$(echo "$i"| awk -F/ '{print $3}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $3}')" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
     skopeo copy --additional-tag $i docker://"$i" docker-archive:cert/"$(echo "$i"| awk -F/ '{print $3}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $3}')" > /dev/null 2>&1
    fi
  done

  echo - skopeo - Neuvector
  for i in $(cat neuvector/neuvector-images.txt); do 
    skopeo inspect docker-archive:neuvector/"$(echo "$i"| awk -F/ '{print $3}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $3}')" > /dev/null
    if [ $? -ne 0 ]; then
     skopeo copy --additional-tag $i docker://"$i" docker-archive:neuvector/"$(echo "$i"| awk -F/ '{print $3}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $3}')" > /dev/null 2>&1
    fi
  done

  echo - skopeo - longhorn
  for i in $(cat longhorn/longhorn-images.txt); do 
    skopeo inspect docker-archive:longhorn/"$(echo "$i"| awk -F/ '{print $2}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $2}')" > /dev/null 
    if [ $? -ne 0 ]; then
     skopeo copy --additional-tag $i docker://"$i" docker-archive:longhorn/"$(echo "$i"| awk -F/ '{print $2}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $2}')" > /dev/null 2>&1
    fi
  done

  echo - skopeo - Rancher - be patient...
  for i in $(cat rancher/rancher-images.txt); do 
    skopeo inspect docker-archive:rancher/"$(echo "$i"| awk -F/ '{print $2}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $2}')" > /dev/null
    if [ $? -ne 0 ]; then
     skopeo copy --additional-tag $i docker://"$i" docker-archive:rancher/"$(echo "$i"| awk -F/ '{print $2}'|sed 's/:/_/g')".tar:"$(echo "$i"| awk -F/ '{print $2}')" > /dev/null 2>&1
    fi
  done

  echo - skopeo add flask app and yaml and registry
  skopeo inspect docker-archive:registry/registry.tar > /dev/null
  if [ $? -ne 0 ]; then
    skopeo copy --additional-tag registry:latest docker://registry:latest docker-archive:registry/registry.tar > /dev/null 2>&1
  fi
  skopeo inspect docker-archive:flask/redis.tar > /dev/null
  if [ $? -ne 0 ]; then
    skopeo copy --additional-tag redis:latest docker://redis docker-archive:flask/redis.tar > /dev/null 2>&1
  fi
  skopeo inspect docker-archive:flask/mongo.tar > /dev/null
  if [ $? -ne 0 ]; then
   skopeo copy --additional-tag mongo:latest docker://mongo docker-archive:flask/mongo.tar > /dev/null 2>&1
  fi
  skopeo inspect docker-archive:flask/flask_simple.tar > /dev/null
  if [ $? -ne 0 ]; then
   skopeo copy --additional-tag clemenko/flask_simple:latest docker://clemenko/flask_simple docker-archive:flask/flask_simple.tar > /dev/null 2>&1
  fi
  curl -#L https://raw.githubusercontent.com/clemenko/rke_airgap_install/main/flask.yaml -o /opt/rancher/images/flask/flask.yaml > /dev/null 2>&1

  echo - load images for longhorn
  for file in $(ls /opt/rancher/images/longhorn/ | grep -v txt ); do 
    skopeo copy docker-archive:/opt/rancher/images/longhorn/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk -F_ '{print "localhost:5000/longhornio/"$1":"$2}')" --dest-tls-verify=false
  done

  echo - load images for CertManager
  for file in $(ls /opt/rancher/images/cert/ | grep -v txt ); do 
    skopeo copy docker-archive:/opt/rancher/images/cert/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk -F_ '{print "localhost:5000/cert/"$1":"$2}')" --dest-tls-verify=false
  done

  echo - load images for Neuvector
  for file in $(ls /opt/rancher/images/neuvector/ | grep -v txt ); do 
    skopeo copy docker-archive:/opt/rancher/images/neuvector/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk -F_ '{print "localhost:5000/neuvector/"$1":"$2}')" --dest-tls-verify=false
  done

  echo - load images for Rancher
  for file in $(ls /opt/rancher/images/rancher/ | grep -v txt ); do 
    skopeo copy docker-archive:/opt/rancher/images/rancher/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk -F_ '{print "localhost:5000/rancher/"$1":"$2}')" --dest-tls-verify=false
  done

  echo - load images for Flask
  for file in $(ls /opt/rancher/images/flask/ | grep -v yaml ); do 
     skopeo copy docker-archive:/opt/rancher/images/flask/"$file" docker://"$(echo "$file" | sed 's/.tar//g' | awk '{print "localhost:5000/flask/"$1}')" --dest-tls-verify=false
  done

  # Verify Image upload
  crane catalog localhost:5000
  crane copy busybox:1.36 localhost:5000/library/busybox:1.36
  crane catalog localhost:5000

  cd /opt/rancher/
  echo - compress all the things
  if ! test -f /opt/rke2_rancher_longhorn.zst; then
   tar -I zstd -vcf /opt/rke2_rancher_longhorn.zst $(ls) > /dev/null 2>&1
  fi

  echo - Setup nfs
  # share out opt directory
  echo "/opt/rancher *(ro)" > /etc/exports
  systemctl enable nfs-server.service && systemctl start nfs-server.service

  # look at adding encryption - https://medium.com/@lumjjb/encrypting-container-images-with-skopeo-f733afb1aed4  

  echo "------------------------------------------------------------------"
  echo " to uncompress : "
  echo "   yum install -y zstd"
  echo "   mkdir /opt/rancher"
  echo "   tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher"
  echo "------------------------------------------------------------------"

}

################################# LB Setup ################################
function lbsetup () {

  echo - Configuring HAProxy Server
  yum install haproxy -y 

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

setsebool -P haproxy_connect_any 1
systemctl start haproxy;systemctl enable haproxy

firewall-cmd --add-port=6443/tcp --permanent
firewall-cmd --add-port=443/tcp --permanent
firewall-cmd --add-service=http --permanent
firewall-cmd --add-service=https --permanent
firewall-cmd --add-port=9000/tcp --permanent
firewall-cmd --reload

}

################################# base ################################
function base () {
  # install all the base bits.

  echo " updating kernel settings"
  cat << EOF >> /etc/sysctl.conf
# SWAP settings
vm.swappiness=0
vm.panic_on_oom=0
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
vm.max_map_count = 262144

# Have a larger connection range available
net.ipv4.ip_local_port_range=1024 65000

# Increase max connection
net.core.somaxconn=10000

# Reuse closed sockets faster
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15

# The maximum number of "backlogged sockets".  Default is 128.
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096

# 16MB per socket - which sounds like a lot,
# but will virtually never consume that much.
net.core.rmem_max=16777216
net.core.wmem_max=16777216

# Various network tunables
net.ipv4.tcp_max_syn_backlog=20480
net.ipv4.tcp_max_tw_buckets=400000
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_wmem=4096 65536 16777216

# ARP cache settings for a highly loaded docker swarm
net.ipv4.neigh.default.gc_thresh1=8096
net.ipv4.neigh.default.gc_thresh2=12288
net.ipv4.neigh.default.gc_thresh3=16384

# ip_forward and tcp keepalive for iptables
net.ipv4.tcp_keepalive_time=600
net.ipv4.ip_forward=1

# monitor file system events
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
EOF
sysctl -p > /dev/null 2>&1

  echo install packages
  yum install -y zstd nfs-utils iptables skopeo container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils
  systemctl enable --now iscsid
  echo -e "[keyfile]\nunmanaged-devices=interface-name:cali*;interface-name:flannel*" > /etc/NetworkManager/conf.d/rke2-canal.conf
}

################################# Deploy Master 1 ################################
function deploy_control1 () {
  # this is for the first node
  # mkdir /opt/rancher
  # tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher

  # Stopping and disabling firewalld & SELinux
  systemctl stop firewalld; systemctl disable firewalld
  setenforce 0
  sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

  echo install packages
  yum install -y zstd nfs-utils iptables skopeo container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils

  # Mount from Build server
  mkdir /opt/rancher
  mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  #base

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
EOF

  echo - Install rke2
  cd /opt/rancher/rke2_$RKE_VERSION

  # set up audit policy file
  #echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse" > /etc/rancher/rke2/audit-policy.yaml

  # set up ssl passthrough for nginx
  #echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml

  # pre-load registry image
  #rsync -avP /opt/rancher/images/registry/registry.tar /var/lib/rancher/rke2/agent/images/

 # insall rke2 - stig'd
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
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

  # Stopping and disabling firewalld & SELinux
  systemctl stop firewalld; systemctl disable firewalld
  setenforce 0
  sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

  echo install packages
  yum install -y zstd nfs-utils iptables skopeo container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils

  # Mount from Build server
  mkdir /opt/rancher
  mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  #base

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

  # set up audit policy file
  #echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse" > /etc/rancher/rke2/audit-policy.yaml

  # set up ssl passthrough for nginx
  #echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml

  # pre-load registry image
  #rsync -avP /opt/rancher/images/registry/registry.tar /var/lib/rancher/rke2/agent/images/

 # insall rke2 - stig'd
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm
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

  # Stopping and disabling firewalld & SELinux
  systemctl stop firewalld; systemctl disable firewalld
  setenforce 0
  sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

  echo install packages
  yum install -y zstd nfs-utils iptables skopeo container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils cryptsetup iscsi-initiator-utils

  # Mount from Build server
  mkdir /opt/rancher
  mount $BUILD_SERVER_IP:/opt/rancher /opt/rancher

  #base

  # Setting up Kubernetes Master using RKE2
  mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/ /var/lib/rancher/rke2/agent/images 
  cp /opt/rancher/rke2_$RKE_VERSION/registries.yaml /etc/rancher/rke2/registries.yaml

cat << EOF >  /etc/rancher/rke2/config.yaml
server: https://MASTERIP1:9345
token: pkls-secret
node-label:
- "region=worker"
EOF

  # check for mount point
  #if [ ! -f /opt/rancher/token ]; then echo " -$RED Did you mount the volume from the first node?$NO_COLOR"; exit 1; fi

  #export token=$(cat /opt/rancher/token)
  #export server=$(mount |grep rancher | awk -F: '{print $1}')

  # setup RKE2
  mkdir -p /etc/rancher/rke2/
  echo -e "server: https://$LB_IP:9345\ntoken: $token\nwrite-kubeconfig-mode: 0600\n#profile: cis-1.23\nkube-apiserver-arg:\n- \"authorization-mode=RBAC,Node\"\nkubelet-arg:\n- \"protect-kernel-defaults=true\" " > /etc/rancher/rke2/config.yaml

  # install rke2
  cd /opt/rancher
  INSTALL_RKE2_ARTIFACT_PATH=/opt/rancher/rke2_"$RKE_VERSION" INSTALL_RKE2_TYPE=agent sh /opt/rancher/rke2_"$RKE_VERSION"/install.sh 
  yum install -y /opt/rancher/rke2_"$RKE_VERSION"/rke2-common-"$RKE_VERSION".rke2r1-0."$EL".x86_64.rpm /opt/rancher/rke2_"$RKE_VERSION"/rke2-selinux-0.17-1."$EL".noarch.rpm

  #rsync -avP /opt/rancher/images/registry/registry.tar /var/lib/rancher/rke2/agent/images/
  
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
  echo " Usage: $0 {build | deploy}"
  echo ""
  echo " $0 build # download and create the monster TAR "
  echo " $0 control # deploy on a control plane server"
  echo " $0 worker # deploy on a worker"
  echo " $0 flask # deploy a 3 tier app"
  echo " $0 neuvector # deploy neuvector"
  echo " $0 longhorn # deploy longhorn"
  echo " $0 rancher # deploy rancher"
  echo " $0 validate # validate all the image locations"
  echo ""
  echo "-------------------------------------------------"
  echo ""
  echo "Steps:"
  echo " - UNCLASS - $0 build"
  echo " - Move the ZST file across the air gap"
  echo " - Build 3 vms with 4cpu and 8gb of ram"
  echo " - On 1st node ( Control Plane node ) run: mkdir /opt/rancher && tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher"
  echo " - On 1st node run cd /opt/rancher; $0 control"
  echo " - Wait and watch for errors"
  echo " - On 2nd, and 3rd nodes run mkdir /opt/rancher && mount \$IP:/opt/rancher /opt/rancher"
  echo " - On 2nd, and 3rd nodes run $0 worker"
  echo " - On 1st node install"
  echo "   - Longhorn : $0 longhorn"
  echo "   - Rancher : $0 rancher"
  echo "   - Flask : $0 flask"
  echo ""
  echo "-------------------------------------------------"
  echo ""
  exit 1
}

case "$1" in
        build ) build;;
        lbsetup ) lbsetup;;
        control1) deploy_control1;;
        control23) deploy_control23;;
        worker) deploy_worker;;
        neuvector) neuvector;;
        longhorn) longhorn;;
        rancher) rancher;;
        flask) flask;;
        validate) validate;;
        *) usage;;
esac
