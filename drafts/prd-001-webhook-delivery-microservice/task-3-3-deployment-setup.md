# Task 3.3: Deployment Setup

**Task ID:** T3-003  
**Phase:** Phase 3 - Testing & Deployment  
**Duration:** 6 days  
**Assignee:** DevOps Engineer  
**Priority:** Critical  

## Overview

This task involves setting up the complete deployment infrastructure for the Webhook Delivery Microservice. This includes creating deployment manifests, configuring CI/CD pipelines, implementing canary deployment strategies, setting up rollback mechanisms, and establishing operational procedures. The deployment setup will ensure zero-d downtime deployments, proper monitoring, and quick rollback capabilities.

## Prerequisites

- All tests passing (Tasks 3.1, 3.2)
- Infrastructure provisioned (Task 1.1)
- Monitoring configured (Task 1.2)
- Security reviews completed
- Deployment approval received

## Detailed Steps

### Step 1: Create Kubernetes Manifests (Day 1)
1. Namespace and RBAC configuration
2. Deployment manifests
3. Service configurations
4. Ingress rules
5. ConfigMaps and Secrets

```yaml
# manifests/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: webhook-service
  labels:
    name: webhook-service
    environment: production

---
# manifests/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: webhook-service
  namespace: webhook-service

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: webhook-service
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: webhook-service
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: webhook-service
subjects:
- kind: ServiceAccount
  name: webhook-service
  namespace: webhook-service

---
# manifests/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: webhook-service-config
  namespace: webhook-service
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
      readTimeout: "30s"
      writeTimeout: "30s"
    
    database:
      host: "postgres-primary.database.svc.cluster.local"
      port: 5432
      name: "webhook_delivery"
      maxOpenConns: 100
      maxIdleConns: 20
      connMaxLifetime: "1h"
    
    redis:
      host: "redis-cluster.message-broker.svc.cluster.local"
      port: 6379
      poolSize: 50
      minIdleConns: 10
    
    rabbitmq:
      url: "amqp://webhook-service:password@rabbitmq.message-broker.svc.cluster.local:5672/"
      prefetchCount: 100
    
    webhook:
      maxPayloadSize: 1048576  # 1MB
      defaultTimeout: "30s"
      queueDepth: 10000
      retryAttempts: 3
    
    monitoring:
      prometheus:
        enabled: true
        path: "/metrics"
      jaeger:
        enabled: true
        endpoint: "http://jaeger-collector.monitoring.svc.cluster.local:14268/api/traces"

---
# manifests/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-service
  namespace: webhook-service
  labels:
    app: webhook-service
    version: v1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%
      maxSurge: 25%
  selector:
    matchLabels:
      app: webhook-service
  template:
    metadata:
      labels:
        app: webhook-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: webhook-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: webhook-service
        image: company/webhook-service:v1.0.0
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: CONFIG_PATH
          value: "/etc/webhook-service/config.yaml"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: webhook-service-secrets
              key: jwt-secret
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: webhook-service-secrets
              key: database-password
        - name: KMS_KEY_ID
          valueFrom:
            configMapKeyRef:
              name: webhook-service-config
              key: kms-key-id
        volumeMounts:
        - name: config
          mountPath: /etc/webhook-service
          readOnly: true
        - name: tmp
          mountPath: /tmp
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        lifecycle:
          preStop:
            httpGet:
              path: /shutdown
              port: http
      volumes:
      - name: config
        configMap:
          name: webhook-service-config
      - name: tmp
        emptyDir: {}
      terminationGracePeriodSeconds: 30
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - webhook-service
              topologyKey: kubernetes.io/hostname

---
# manifests/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: webhook-service
  namespace: webhook-service
  labels:
    app: webhook-service
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: http
    protocol: TCP
    name: http
  - port: 9090
    targetPort: metrics
    protocol: TCP
    name: metrics
  selector:
    app: webhook-service

---
# manifests/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: webhook-service
  namespace: webhook-service
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "1000"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.webhooks.company.com
    secretName: webhook-service-tls
  rules:
  - host: api.webhooks.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: webhook-service
            port:
              number: 80

---
# manifests/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: webhook-service-hpa
  namespace: webhook-service
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: webhook-service
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

### Step 2: Setup CI/CD Pipeline (Day 2)
1. Build pipeline configuration
2. Test automation integration
3. Security scanning
4. Image scanning
5. Deployment automation

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    tags:
      - 'v*'

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: company/webhook-service

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    outputs:
      image: ${{ steps.meta.outputs.tags }}
      digest: ${{ steps.build.outputs.digest }}
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
    
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
    
    - name: Build and push Docker image
      id: build
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
    
    - name: Run tests
      run: |
        docker run --rm \
          ${{ steps.meta.outputs.tags }} \
          make test
    
    - name: Security scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'

  deploy-staging:
    needs: build-and-test
    runs-on: ubuntu-latest
    environment: staging
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v1
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG }}
    
    - name: Deploy to staging
      run: |
        helm upgrade --install webhook-service-staging ./helm/webhook-service \
          --namespace webhook-service-staging \
          --create-namespace \
          --set image.repository=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }} \
          --set image.tag=${{ github.ref_name }} \
          --set environment=staging \
          --set ingress.host=staging.api.webhooks.company.com \
          --values helm/values-staging.yaml \
          --wait \
          --timeout 10m
    
    - name: Run smoke tests
      run: |
        ./scripts/smoke-tests.sh https://staging.api.webhooks.company.com

  canary-deploy:
    needs: [build-and-test, deploy-staging]
    runs-on: ubuntu-latest
    environment: production
    if: contains(github.ref, 'rc')
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v1
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG }}
    
    - name: Deploy canary
      run: |
        helm upgrade --install webhook-service-canary ./helm/webhook-service-canary \
          --namespace webhook-service \
          --set image.repository=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }} \
          --set image.tag=${{ github.ref_name }} \
          --set canary.enabled=true \
          --set canary.percent=5 \
          --values helm/values-prod.yaml
    
    - name: Wait for canary to stabilize
      run: |
        ./scripts/wait-for-canary.sh webhook-service prod 600
    
    - name: Analyze canary metrics
      run: |
        ./scripts/analyze-canary.sh webhook-service prod
    
    - name: Approve canary promotion
      uses: trstringer/manual-approval@v1
      with:
        secret: ${{ github.TOKEN }}
        approvers: devops-lead,engineering-manager
        minimum-approvals: 2
    
    - name: Promote to full production
      if: success()
      run: |
        helm upgrade webhook-service ./helm/webhook-service \
          --namespace webhook-service \
          --reuse-values \
          --set image.tag=${{ github.ref_name }} \
          --set canary.enabled=false

  production-deploy:
    needs: build-and-test
    runs-on: ubuntu-latest
    environment: production
    if: (!contains(github.ref, 'rc')) && startsWith(github.ref, 'refs/tags/v')
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v1
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG }}
    
    - name: Deploy to production
      run: |
        helm upgrade --install webhook-service ./helm/webhook-service \
          --namespace webhook-service \
          --reuse-values \
          --set image.tag=${{ github.ref_name }} \
          --set deployment.strategy=rollingUpdate
    
    - name: Verify deployment
      run: |
        kubectl rollout status deployment/webhook-service -n webhook-service --timeout=300s
        ./scripts/verify-deployment.sh
```

```yaml
# helm/webhook-service/Chart.yaml
apiVersion: v2
name: webhook-service
description: Webhook Delivery Microservice
type: application
version: 1.0.0
appVersion: "1.0.0"

dependencies:
- name: postgresql
  version: 12.1.9
  repository: https://charts.bitnami.com/bitnami
  condition: postgresql.enabled

- name: redis
  version: 17.3.7
  repository: https://charts.bitnami.com/bitnami
  condition: redis.enabled
```

### Step 3: Configure Canary Deployment (Day 3)
1. Argo Rollouts configuration
2. Traffic splitting setup
3. Canary analysis templates
4. Automated promotion rules

```yaml
# manifests/rollout.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: webhook-service
  namespace: webhook-service
spec:
  replicas: 3
  strategy:
    type: Canary
    steps:
    - setWeight: 5
    - pause: {duration: 10m}
    - setWeight: 25
    - pause: {duration: 10m}
    - setWeight: 50
    - pause: {duration: 10m}
    - setWeight: 100
    canaryService: webhook-service-canary
    stableService: webhook-service-stable
    trafficRouting:
      istio:
        virtualService:
          name: webhook-service-vsvc
          routes:
          - primary
    analysis:
      templates:
      - templateName: success-rate
      - templateName: latency
      args:
      - name: service-name
        value: webhook-service-canary
      startingStep: 2
      interval: 5m
  selector:
    matchLabels:
      app: webhook-service
  template:
    metadata:
      labels:
        app: webhook-service
    spec:
      containers:
      - name: webhook-service
        image: company/webhook-service:{{ .Values.image.tag }}
        ports:
        - containerPort: 8080
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi

---
apiVersion: v1
kind: Service
metadata:
  name: webhook-service-stable
  namespace: webhook-service
spec:
  selector:
    app: webhook-service
  ports:
  - port: 80
    targetPort: 8080

---
apiVersion: v1
kind: Service
metadata:
  name: webhook-service-canary
  namespace: webhook-service
spec:
  selector:
    app: webhook-service
  ports:
  - port: 80
    targetPort: 8080

---
# manifests/analysis-templates.yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: success-rate
spec:
  args:
  - name: service-name
  metrics:
  - name: success-rate
    interval: 5m
    count: 12
    successCondition: result[0] >= 0.99
    provider:
      prometheus:
        address: http://prometheus.monitoring.svc.cluster.local:9090
        query: |
          sum(
            rate(http_requests_total{service="{{args.service-name}}",code!~"5.."}[5m])
          ) /
          sum(
            rate(http_requests_total{service="{{args.service-name}}"}[5m])
          )

---
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: latency
spec:
  args:
  - name: service-name
  metrics:
  - name: latency
    interval: 5m
    count: 12
    successCondition: result[0] <= 0.5
    provider:
      prometheus:
        address: http://prometheus.monitoring.svc.cluster.local:9090
        query: |
          histogram_quantile(0.95,
            sum(rate(http_request_duration_seconds_bucket{service="{{args.service-name}}"}[5m])) by (le)
          )
```

### Step 4: Create Rollback Procedures (Day 4)
1. Rollback automation scripts
2. Database migration rollback
3. Configuration rollback
4. Emergency procedures

```bash
#!/bin/bash
# scripts/rollback.sh

set -euo pipefail

ROLLBACK_VERSION=${1:-""}
NAMESPACE=${2:-"webhook-service"}
DRY_RUN=${3:-false}

if [ -z "$ROLLBACK_VERSION" ]; then
    echo "Usage: $0 <version> [namespace] [dry-run]"
    echo "Available versions:"
    helm history webhook-service -n $NAMESPACE | tail -10
    exit 1
fi

echo "Rolling back to version: $ROLLBACK_VERSION"
echo "Namespace: $NAMESPACE"
echo "Dry run: $DRY_RUN"
echo

# Check if version exists
if ! helm history webhook-service -n $NAMESPACE | grep -q "$ROLLBACK_VERSION"; then
    echo "Error: Version $ROLLBACK_VERSION not found for webhook-service in namespace $NAMESPACE"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(helm get values webhook-service -n $NAMESPACE -o json | jq -r '.image.tag // "unknown"')
echo "Current version: $CURRENT_VERSION"

# Pre-rollback checks
echo "Running pre-rollback checks..."

# Check deployment status
DEPLOY_STATUS=$(kubectl get deployment webhook-service -n $NAMESPACE -o json | jq -r '.status.conditions[] | select(.type=="Progressing") | .status')
if [ "$DEPLOY_STATUS" != "False" ]; then
    echo "Warning: Deployment is in a progressing state"
fi

# Check pod health
UNHEALTHY_PODS=$(kubectl get pods -n $NAMESPACE -l app=webhook-service --field-selector=status.phase!=Running,status.phase!=Succeeded --no-headers | wc -l)
if [ "$UNHEALTHY_PODS" -gt 0 ]; then
    echo "Warning: Found $UNHEALTHY_PODS unhealthy pods"
fi

# Backup current state if not dry run
if [ "$DRY_RUN" != "true" ]; then
    BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    echo "Backing up current state to $BACKUP_DIR"
    kubectl get deployment webhook-service -n $NAMESPACE -o yaml > "$BACKUP_DIR/deployment.yaml"
    kubectl get configmap webhook-service-config -n $NAMESPACE -o yaml > "$BACKUP_DIR/configmap.yaml"
    helm get values webhook-service -n $NAMESPACE > "$BACKUP_DIR/helm-values.yaml"
fi

# Perform rollback
echo "Rolling back to version $ROLLBACK_VERSION..."
ROLLBACK_CMD="helm rollback webhook-service $ROLLBACK_VERSION -n $NAMESPACE"

if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN: Would execute: $ROLLBACK_CMD"
else
    $ROLLBACK_CMD
    
    echo "Waiting for rollback to complete..."
    kubectl rollout status deployment/webhook-service -n $NAMESPACE --timeout=300s
    
    # Post-rollback verification
    echo "Running post-rollback verification..."
    
    # Check pod status
    kubectl get pods -n $NAMESPACE -l app=webhook-service
    
    # Run health check
    HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" http://webhook-service.$NAMESPACE.svc.cluster.local/health)
    if [ "$HEALTH_CHECK" = "200" ]; then
        echo "✅ Health check passed"
    else
        echo "❌ Health check failed (status: $HEALTH_CHECK)"
        exit 1
    fi
    
    # Verify version
    VERIFIED_VERSION=$(kubectl get deployment webhook-service -n $NAMESPACE -o jsonpath='{.spec.template.spec.containers[0].image}' | cut -d: -f2)
    echo "Verified version: $VERIFIED_VERSION"
    
    if [ "$VERIFIED_VERSION" != "$ROLLBACK_VERSION" ]; then
        echo "❌ Version mismatch after rollback"
        exit 1
    fi
fi

echo "Rollback completed successfully!"
```

### Step 5: Setup Monitoring and Alerts (Day 5)
1. Deployment monitoring
2. Prometheus rules for deployments
3. Grafana dashboards
4. Alert configurations

```yaml
# manifests/monitoring.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: webhook-service
  namespace: webhook-service
  labels:
    app: webhook-service
spec:
  selector:
    matchLabels:
      app: webhook-service
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics

---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: webhook-service
  namespace: webhook-service
spec:
  groups:
  - name: deployment.rules
    rules:
    - alert: DeploymentRolloutFailed
      expr: kube_deployment_status_replicas_unavailable{deployment="webhook-service"} > 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Webhook Service deployment rollout failed"
        description: "Deployment {{ $labels.deployment }} has {{ $value }} unavailable replicas"
    
    - alert: HighErrorRate
      expr: rate(http_requests_total{service="webhook-service",code=~"5.."}[5m]) / rate(http_requests_total{service="webhook-service"}[5m]) > 0.05
      for: 2m
      labels:
        severity: warning
        annotations:
        summary: "High error rate detected"
        description: "Error rate is {{ $value | humanizePercentage }}"
    
    - alert: HighLatency
      expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{service="webhook-service"}[5m])) > 0.5
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High latency detected"
        description: "P95 latency is {{ $value }}s"
```

### Step 6: Documentation and Training (Day 6)
1. Deployment playbooks
2. Run procedures
3. Incident response
4. Operator training

```markdown
# Deployment Operations Manual

## Table of Contents
1. [Deployment Overview](#deployment-overview)
2. [Standard Deployment](#standard-deployment)
3. [Canary Deployment](#canary-deployment)
4. [Rollback Procedures](#rollback-procedures)
5. [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
6. [Emergency Procedures](#emergency-procedures)

## Deployment Overview

The Webhook Delivery Microservice uses GitOps-based deployment with the following workflow:
1. Code push triggers CI/CD pipeline
2. Automated tests run
3. Docker image built and scanned
4. Deployment to staging
5. Canary deployment to production (for release candidates)
6. Full production deployment (for stable releases)

## Standard Deployment

### Prerequisites
- All tests passing
- Security scan clean
- Deployment branch merged
- Required approvals received

### Steps
1. Tag the release:
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

2. Monitor deployment:
   ```bash
   kubectl get rollout -n webhook-service
   kubectl logs -f deployment/webhook-service -n webhook-service
   ```

3. Verify deployment:
   ```bash
   ./scripts/verify-deployment.sh
   ```

## Canary Deployment

Canary deployments are used for release candidates (vX.Y.Z-rc.N).

### Process
1. Deploy to 5% of traffic
2. Monitor for 10 minutes
3. Increase to 25% if metrics look good
4. Monitor for 10 minutes
5. Increase to 50% if metrics look good
6. Full promotion after final check

### Monitoring Metrics
- Error rate < 0.5%
- P95 latency < 500ms
- Success rate > 99.5%

## Rollback Procedures

### Automatic Rollback
- Triggered by alert conditions
- Automated script execution
- Notification to on-call

### Manual Rollback
1. Identify rollback version:
   ```bash
   helm history webhook-service -n webhook-service
   ```

2. Execute rollback:
   ```bash
   ./scripts/rollback.sh <version> webhook-service
   ```

3. Verify rollback:
   ```bash
   kubectl rollout status deployment/webhook-service -n webhook-service
   curl http://webhook-service.webhook-service.svc.cluster.local/health
   ```

## Monitoring and Troubleshooting

### Key Dashboards
1. Deployment Status
2. Performance Metrics
3. Error Analysis
4. Resource Utilization

### Common Issues
1. **Pods not starting**
   - Check resource limits
   - Verify image exists
   - Check RBAC permissions

2. **High latency**
   - Check database connections
   - Verify queue depth
   - Check resource utilization

3. **Rollouts stuck**
   - Check image pull secret
   - Verify registry access
   - Check readiness probe

## Emergency Procedures

### Service Down
1. Immediate rollback to last stable version
2. Alert all stakeholders
3. Begin incident investigation

### Database Issues
1. Switch to read replica if available
2. Scale down service to reduce load
3. Engage DB team immediately

### Infrastructure Failure
1. Check cluster health
2. Verify networking
3. Engage infrastructure team
```

## Acceptance Criteria

### Must-Have
- [ ] Zero-downtime deployments
- [ ] Automated rollback on failure
- [ ] Canary deployment working
- [ ] All deployments monitored
- [ ] Documentation complete
- [ ] Team trained on procedures

### Should-Have
- [ ] Automated testing in pipeline
- [ ] Blue-green deployment option
- [ ] Feature flag support
- [ ] Deployment analytics
- [ ] Post-deployment verification

### Could-Have
- [ ] A/B testing capabilities
- [ ] Progressive delivery
- [ ] Chaos engineering
- [ ] Predictive scaling

## Deployment Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Deployment time | < 15 min | From tag to service |
| Rollback time | < 5 min | From trigger to complete |
| Downtime | 0 seconds | Per deployment |
| Success rate | 99%+ | Successful deployments |
| Mean time to recovery | < 10 min | From incident to fix |

## Deliverables

1. **Deployment Manifests**
   - Kubernetes YAML files
   - Helm charts
   - ConfigMaps and Secrets
   - RBAC configurations

2. **CI/CD Pipeline**
   - GitHub Actions workflows
   - Build scripts
   - Test automation
   - Security scanning

3. **Monitoring Setup**
   - Service monitors
   - Alert rules
   - Dashboards
   - Log aggregation

4. **Documentation**
   - Deployment guide
   - Runbook
   - Troubleshooting manual
   - Training materials

---

## Checklists

### Pre-Deployment Checklist
- [ ] Tests passing
- [ ] Security scan clean
- [ ] Documentation updated
- [ ] Stakeholders notified
- [ ] Backup procedure ready

### Post-Deployment Checklist
- [ ] Service healthy
- [ ] Metrics normal
- [ ] No errors in logs
- [ ] Users notified
- [ ] Rollback window closed

---

*Reviewer: DevOps Lead, SRE Team*  
* Approved by: Engineering Director, Operations Manager*  
* Completion Date: Expected 2025-04-04*