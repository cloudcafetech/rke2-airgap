#test


podman save --output registry.tar docker.io/library/registry:latest 

ctr -a /var/run/containerd/containerd.sock namespace ls

ctr -a /var/run/containerd/containerd.sock --namespace k8s.io image import --base-name docker.io/library/registry:latest registry.tar


while IFS= read -r img; do
    echo "Text read from file: $img"
done < quay.txt

while IFS= read -r img; do  
  IMG=`echo $img | cut -d "/" -f3 | cut -d ":" -f1`
  podman pull $img
  podman save --output "$IMG".tar $img
done < quay.txt

tar cf - quay-images/ | zstd > quay-images.tar.zst

----------------

registry.k8s.io/ingress-nginx/controller:v1.8.2@sha256:74834d3d25b336b62cabeb8bf7f1d788706e2cf1cfd64022de4137ade8881ff2
registry.k8s.io/ingress-nginx/controller:v1.8.1@sha256:e5c4824e7375fcf2a393e1c03c293b69759af37a9ca6abdb91b13d78a93da8bd
registry.k8s.io/ingress-nginx/kube-webhook-certgen:v20230407@sha256:543c40fd093964bc9ab509d3e791f9989963021f1e9e4c9c7b6700b02bfb227b
registry.k8s.io/metrics-server/metrics-server:v0.7.0

ghcr.io/stakater/reloader:v1.0.69
ghcr.io/dexidp/dex:v2.36.0
ghcr.io/dexidp/dex:v2.30.0
gcr.io/heptio-images/gangway:v3.2.0
gcr.io/kuar-demo/kuard-amd64:1
k8s.gcr.io/addon-resizer:1.7

quay.io/minio/minio:latest
quay.io/coreos/kube-state-metrics:v1.9.6
quay.io/prometheus/alertmanager:v0.16.0
quay.io/prometheus/node-exporter:v0.18.1
quay.io/prometheus/prometheus:v2.19.1
quay.io/oauth2-proxy/oauth2-proxy:latest
quay.io/thanos/thanos:v0.31.0
quay.io/argoproj/argocd:v2.6.9
quay.io/jetstack/cert-manager-acmesolver:v1.13.3
quay.io/jetstack/cert-manager-cainjector:v1.13.3
quay.io/jetstack/cert-manager-controller:v1.13.3
quay.io/jetstack/cert-manager-webhook:v1.13.3
quay.io/jetstack/cert-manager-ctl:v1.13.3
quay.io/openshift/origin-console:4.18

docker.io/debian:9
docker.io/haproxy:2.6.12-alpine
docker.io/redis:7.0.11-alpine
docker.io/grafana/loki:3.0.0
docker.io/memcached:1.6.23-alpine
docker.io/prom/memcached-exporter:v0.14.2
docker.io/grafana/loki-canary:3.0.0
docker.io/nginxinc/nginx-unprivileged:1.24-alpine
docker.io/kiwigrid/k8s-sidecar:1.24.3
docker.io/grafana/fluent-bit-plugin-loki:main-e2ed1c0
docker.io/grafana/loki:2.8.0       
docker.io/grafana/promtail:1.5.0
docker.io/bitnami/sealed-secrets-controller:0.26.3
docker.io/bitnami/minio:2024.5.1-debian-12-r0
docker.io/velero/velero-plugin-for-aws:v1.9.2
docker.io/rancher/local-path-provisioner:v0.0.24
docker.io/busybox:latest
docker.io/minio/minio:latest
docker.io/flannel/flannel:v0.24.2
docker.io/flannel/flannel-cni-plugin:v1.4.0-flannel1
docker.io/kubernetesui/dashboard:v2.7.0
docker.io/kubernetesui/metrics-scraper:v1.0.8
docker.io/grafana/loki:2.0.0-amd64
docker.io/grafana/loki:2.8.0
docker.io/grafana/fluent-bit-plugin-loki:0.1
docker.io/grafana/fluent-bit-plugin-loki:latest
docker.io/grafana/grafana:8.5.13
docker.io/grafana/promtail:2.8.3

docker.io/library/registry:latest
