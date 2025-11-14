# Deployment Guide

## Overview

This guide covers deploying Provenix in various environments with zero-trust security configurations.

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+, RHEL 8+, or equivalent)
- **Container Runtime**: Docker 24.0+ or Podman 4.0+
- **Orchestration**: Kubernetes 1.28+ (for production)
- **Database**: PostgreSQL 15+
- **Policy Engine**: Open Policy Agent (OPA) 0.50+

### Security Requirements
- **TLS Certificates**: Valid certificates for all services
- **HSM/TPM**: Hardware security module for key management (recommended)
- **Identity Provider**: OIDC-compatible identity provider
- **Network Security**: Firewall rules and network segmentation

## Local Development Deployment

### Using Docker Compose

1. **Clone the repository**:
```bash
git clone https://github.com/your-org/provenix.git
cd provenix
```

2. **Configure environment**:
```bash
cp server/config/dev.toml server/config/local.toml
# Edit local.toml with your specific settings
```

3. **Start services**:
```bash
docker-compose -f infra/docker/compose.yaml up -d
```

4. **Verify deployment**:
```bash
curl http://localhost:8080/health
```

### Manual Setup

1. **Install dependencies**:
```bash
# PostgreSQL
sudo apt-get install postgresql-15

# OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/
```

2. **Setup database**:
```bash
sudo -u postgres createuser provenix
sudo -u postgres createdb provenix_dev -O provenix
```

3. **Build and run**:
```bash
cargo build --release
./target/release/pxs
```

## Production Deployment

### Kubernetes Deployment

#### 1. Prepare Kubernetes Cluster

**Using Terraform**:
```bash
cd infra/terraform
terraform init
terraform plan -var-file="production.tfvars"
terraform apply
```

**Configure kubectl**:
```bash
aws eks update-kubeconfig --region us-west-2 --name provenix-cluster
```

#### 2. Deploy Core Infrastructure

**Namespace and RBAC**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: provenix
  labels:
    app: provenix
    security.policy/enforce: "strict"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: provenix-server
  namespace: provenix
automountServiceAccountToken: true
```

**PostgreSQL (using CloudNativePG)**:
```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: provenix-postgres
  namespace: provenix
spec:
  instances: 3
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
      ssl: "on"
  storage:
    size: 100Gi
    storageClass: gp3-encrypted
  monitoring:
    enabled: true
```

**OPA Deployment**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opa
  namespace: provenix
spec:
  replicas: 2
  selector:
    matchLabels:
      app: opa
  template:
    metadata:
      labels:
        app: opa
    spec:
      containers:
      - name: opa
        image: openpolicyagent/opa:latest-envoy
        ports:
        - containerPort: 8181
        args:
          - "run"
          - "--server"
          - "--addr=0.0.0.0:8181"
          - "/policies"
        volumeMounts:
        - name: policy-config
          mountPath: /policies
      volumes:
      - name: policy-config
        configMap:
          name: opa-policies
```

#### 3. Deploy Provenix Server

**Deployment Configuration**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: provenix-server
  namespace: provenix
spec:
  replicas: 3
  selector:
    matchLabels:
      app: provenix-server
  template:
    metadata:
      labels:
        app: provenix-server
    spec:
      serviceAccountName: provenix-server
      containers:
      - name: server
        image: ghcr.io/your-org/provenix-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: PROVENIX_ENV
          value: "production"
        - name: PROVENIX__DATABASE__URL
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: url
        - name: PROVENIX__AUTH__JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
```

**Service and Ingress**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: provenix-server
  namespace: provenix
spec:
  selector:
    app: provenix-server
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: provenix-ingress
  namespace: provenix
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.provenix.com
    secretName: provenix-tls
  rules:
  - host: api.provenix.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: provenix-server
            port:
              number: 80
```

### Cloud-Specific Deployments

#### AWS EKS
```bash
# Install AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller//crds?ref=master"

# Deploy with ALB
kubectl apply -f k8s/aws/
```

#### Azure AKS
```bash
# Enable OIDC Issuer
az aks update -g myResourceGroup -n myCluster --enable-oidc-issuer

# Deploy with Application Gateway
kubectl apply -f k8s/azure/
```

#### Google GKE
```bash
# Enable Workload Identity
gcloud container clusters update provenix-cluster \
    --workload-pool=PROJECT_ID.svc.id.goog

# Deploy with Ingress
kubectl apply -f k8s/gcp/
```

## Security Configuration

### TLS/SSL Setup

**Certificate Management with cert-manager**:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@provenix.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

### Network Policies

**Zero Trust Network Policies**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: provenix-network-policy
  namespace: provenix
spec:
  podSelector:
    matchLabels:
      app: provenix-server
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: opa
    ports:
    - protocol: TCP
      port: 8181
```

### Secrets Management

**Using HashiCorp Vault**:
```bash
# Install Vault
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault

# Configure Kubernetes auth
vault auth enable kubernetes
```

**Vault Configuration**:
```hcl
path "secret/provenix/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki/issue/provenix" {
  capabilities = ["create", "update"]
}
```

## Monitoring and Observability

### Metrics Collection

**Prometheus Configuration**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    scrape_configs:
    - job_name: 'provenix'
      static_configs:
      - targets: ['provenix-server:8080']
      metrics_path: /metrics
```

### Logging

**Fluent Bit Configuration**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [INPUT]
        Name tail
        Path /var/log/containers/provenix-*.log
        Parser docker
        Tag provenix.*
    
    [OUTPUT]
        Name es
        Match provenix.*
        Host elasticsearch
        Port 9200
        Index provenix-logs
```

### Alerting

**AlertManager Rules**:
```yaml
groups:
- name: provenix.rules
  rules:
  - alert: ProvenixServerDown
    expr: up{job="provenix"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Provenix server is down"
  
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"
```

## Backup and Recovery

### Database Backup

**Automated Backup with pgBackRest**:
```bash
# Install pgBackRest
sudo apt-get install pgbackrest

# Configure backup
cat > /etc/pgbackrest.conf << EOF
[provenix]
pg1-host=postgres.provenix.svc.cluster.local
pg1-path=/var/lib/postgresql/data

[global]
repo1-type=s3
repo1-s3-bucket=provenix-backups
repo1-s3-region=us-west-2
EOF

# Schedule backups
0 2 * * * pgbackrest --stanza=provenix backup
```

### Disaster Recovery

**Recovery Procedures**:
```bash
# Point-in-time recovery
pgbackrest --stanza=provenix restore --target-time="2024-01-01 12:00:00"

# Full system restore
kubectl apply -f k8s/disaster-recovery/
```

## Performance Tuning

### Database Optimization

**PostgreSQL Configuration**:
```sql
-- Connection settings
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';

-- Performance settings
ALTER SYSTEM SET effective_cache_size = '2GB';
ALTER SYSTEM SET random_page_cost = 1.1;

-- Security settings
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET log_statement = 'mod';
```

### Application Tuning

**Resource Limits**:
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "2Gi"
    cpu: "1000m"
```

**JVM/Runtime Optimization**:
```bash
# Rust-specific optimizations
RUSTFLAGS="-C target-cpu=native"
CARGO_PROFILE_RELEASE_LTO=true
```

## Troubleshooting

### Common Issues

1. **Database Connection Failures**:
```bash
# Check database connectivity
kubectl exec -it provenix-server-xxx -- psql $DATABASE_URL -c "\l"
```

2. **Authentication Issues**:
```bash
# Verify OIDC configuration
curl -s https://your-oidc-provider/.well-known/openid_configuration
```

3. **Policy Engine Errors**:
```bash
# Check OPA policies
kubectl logs -l app=opa
curl http://opa-service:8181/v1/data/provenix/authz
```

### Diagnostic Commands

```bash
# Check cluster status
kubectl get pods -n provenix

# View logs
kubectl logs -f deployment/provenix-server -n provenix

# Port forward for debugging
kubectl port-forward svc/provenix-server 8080:80 -n provenix

# Execute into container
kubectl exec -it deployment/provenix-server -n provenix -- /bin/sh
```

This deployment guide ensures secure, scalable, and maintainable Provenix deployments across various environments while maintaining zero-trust security principles.