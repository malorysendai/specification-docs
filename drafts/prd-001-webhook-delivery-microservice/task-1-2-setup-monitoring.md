# Task 1.2: Setup Monitoring

**Task ID:** T1-002  
**Phase:** Phase 1 - Infrastructure Setup  
**Duration:** 7 days  
**Assignee:** DevOps Engineer  
**Priority:** Critical  

## Overview

This task involves implementing comprehensive monitoring, logging, and alerting infrastructure for the Webhook Delivery Microservice. The solution will provide real-time visibility into system performance, health metrics, and operational status. We'll deploy Prometheus for metrics collection, Grafana for visualization, Loki for log aggregation, and AlertManager for alerting.

## Prerequisites

- Infrastructure from Task 1.1 is operational
- Helm 3.11+ installed and configured
- Monitoring namespace created in Kubernetes
- Persistent storage provisioned for monitoring data
- SSO credentials for Grafana (if using SSO)

## Detailed Steps

### Step 1: Deploy Prometheus (Days 1-2)
1. Install Prometheus Operator using Helm chart
2. Configure ServiceMonitors for all services
3. Set up recording rules for performance metrics
4. Configure remote write for long-term storage
5. Implement Prometheus federation for multi-cluster

```yaml
# prometheus-values.yaml
prometheus:
  prometheusSpec:
    serviceMonitorsSelectorNilUsesHelmValues: false
    serviceMonitorSelector:
      matchLabels:
        team: webhook-delivery
    
    retention: 15d
    retentionSize: 50GB
    
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: gp3
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 100Gi
    
    resources:
      requests:
        cpu: 200m
        memory: 2000Mi
      limits:
        cpu: 1000m
        memory: 4000Mi
    
    ruleSelector:
      matchLabels:
        role: alert-rules
        app: webhook-delivery
```

### Step 2: Configure Graphite Metrics (Day 3)
1. Deploy custom exporters for application metrics
2. Set up webhook-specific metrics
3. Configure service discovery
4. Test metric collection

### Step 3: Deploy Grafana (Day 4)
1. Install Grafana via Helm chart
2. Configure persistence for dashboards
3. Set up Prometheus data source
4. Import pre-built dashboards
5. Configure user authentication (SSO)

```yaml
# grafana-values.yaml
adminPassword: ${GRAFANA_PASSWORD}

datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
      - name: Prometheus
        type: prometheus
        url: http://prometheus-server.monitoring.svc.cluster.local
        access: proxy
        isDefault: true
        
dashboardProviders:
  dashboardproviders.yaml:
    apiVersion: 1
    providers:
      - name: 'default'
        orgId: 1
        folder: ''
        type: file
        disableDeletion: false
        editable: true
        options:
          path: /var/lib/grafana/dashboards/default

dashboards:
  default:
    webhook-overview:
      gnetId: 1860
      revision: 27
      datasource: Prometheus
    kubernetes-overview:
      gnetId: 2
      revision: 1
      datasource: Prometheus
```

### Step 4: Set Up Alerting (Days 5-6)
1. Deploy AlertManager
2. Configure alert routes and receivers
3. Set up PagerDuty integration
4. Create Slack webhook integration
5. Define alert rules and thresholds

```yaml
# alertmanager-config.yaml
global:
  resolve_timeout: 5m

receivers:
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: ${PAGERDUTY_SERVICE_KEY}
        description: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
        
  - name: 'slack'
    slack_configs:
      - api_url: ${SLACK_WEBHOOK_URL}
        channel: '#webhook-alerts'
        title: 'Webhook Delivery Alert'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

route:
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'pagerduty'
  routes:
    - match:
        severity: warning
      receiver: 'slack'
```

### Step 5: Implement Centralized Logging (Day 7)
1. Deploy Loki for log aggregation
2. Install Promtail agents on all nodes
3. Configure LogQL queries
4. Set up log retention policies
5. Test log collection pipeline

```yaml
# loki-values.yaml
loki:
  auth_enabled: false
  
  chunk_store_config:
    max_look_back_period: 0s
    
  table_manager:
    retention_deletes_enabled: true
    retention_period: 168h
    
ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 1h
  max_chunk_age: 1h
```

## Monitoring Metrics Definition

### Application Metrics
```go
// Prometheus metrics definitions
var (
    webhookDeliveries = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "webhook_deliveries_total",
            Help: "Total number of webhook delivery attempts",
        },
        []string{"status", "endpoint"},
    )
    
    webhookDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "webhook_delivery_duration_seconds",
            Help: "Time spent delivering webhook",
            Buckets: prometheus.DefBuckets,
        },
        []string{"endpoint"},
    )
    
    queueDepth = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "webhook_queue_depth",
            Help: "Current number of webhooks in queue",
        },
    )
    
    retryAttempts = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "webhook_retries_total",
            Help: "Total number of retry attempts",
        },
        []string{"attempt_number"},
    )
)
```

### Infrastructure Metrics
- CPU/Memory utilization per pod
- Network I/O and throughput
- Disk usage and IOPS
- Database connections and query performance
- Queue message rates and depths

### Business Metrics
- Webhook success rate (SLA metric)
- Average delivery time
- Customers affected by failures
- Revenue impact of delivery issues

## Dashboard Templates

### Main Dashboard Panels
1. **Overview Panel**
   - Total webhooks queued
   - Delivery success rate (24h)
   - Average delivery time
   - Active endpoints

2. **Performance Panel**
   - P50/P95/P99 latency
   - Throughput (webhooks/sec)
   - Error rate percentage
   - Queue depth over time

3. **Infrastructure Panel**
   - CPU/Memory usage
   - Replica count
   - Pod restarts
   - Network I/O

4. **Alert Panel**
   - Active alerts list
   - Alert history
   - Mean time to resolution
   - Escalation status

## Acceptance Criteria

### Must-Have
- [ ] Prometheus collecting metrics from all services
- [ ] Grafana dashboards created and accessible
- [ ] Alerting sending notifications to PagerDuty
- [ ] Log aggregation working for all pods
- [ ] Retention policies configured:
  - Metrics: 15 days hot, 90 days cold
  - Logs: 14 days
  - Alerts: 30 days

### Should-Have
- [ ] Custom business metrics dashboard
- [ ] Synthetic monitoring setup
- [ ] Correlation IDs in logs
- [ ] SSO integration for Grafana
- [ ] Alert fatigue prevention rules

### Could-Have
- [ ] Machine learning for anomaly detection
- [ ] A/B testing dashboard
- [ ] Cost monitoring dashboard
- [ ] Capacity planning reports

## Alert Rules

### Critical Alerts (PagerDuty)
```yaml
- alert: WebhookHighErrorRate
  expr: rate(webhook_deliveries_total{status="error"}[5m]) / rate(webhook_deliveries_total[5m]) > 0.05
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "High webhook error rate detected"
    description: "Webhook error rate is {{ $value | humanizePercentage }}"

- alert: WebhookQueueBacklog
  expr: webhook_queue_depth > 10000
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Webhook queue backlog growing"
    description: "Queue depth is {{ $value }} messages"
```

### Warning Alerts (Slack)
```yaml
- alert: HighLatency
  expr: histogram_quantile(0.95, rate(webhook_delivery_duration_seconds_bucket[5m])) > 0.5
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "High webhook delivery latency"
    description: "P95 latency is {{ $value }}s"
```

## Testing Plan

1. **Metrics Validation**
   - Verify all custom metrics are exported
   - Check metric labels and types
   - Test metric aggregation

2. **Alert Testing**
   - Trigger artificial errors
   - Verify alert notifications
   - Test alert escalation

3. **Dashboard Testing**
   - Validate data accuracy
   - Check refreshing and loading
   - Test user permissions

4. **Load Testing**
   - Monitor under simulated load
   - Verify metric accuracy
   - Check alert effectiveness

## Deliverables

1. **Monitoring as Code**
   - Helm values files
   - Alert rule definitions
   - Dashboard JSON exports
   - Terraform for external services

2. **Documentation**
   - On-call runbook
   - Metric catalog
   - Alert investigation guide
   - Architecture diagram

3. **Playbooks**
   - Incident response procedures
   - Common troubleshooting steps
   - Performance tuning guide
   - Capacity planning checklist

## Estimated Costs

| Service | Monthly Cost | Notes |
|---------|--------------|-------|
| Prometheus storage | $300 | 100GB gp3 |
| Grafana Cloud | $200 | For backup dashboards |
| PagerDuty | $150 | Business tier |
| Log storage | $400 | 100GB/day retention |
| Total | $1,050 | Estimated |

## Next Steps

After completing monitoring setup:
1. Train operations team
2. Create custom alerts for business metrics
3. Set up automated responses
4. Integrate with incident management system

---

## Checklists

### Pre-Deployment Checklist
- [ ] Storage classes created
- [ ] Service accounts configured
- [ ] Network policies reviewed
- [ ] Backup procedures documented

### Post-Deployment Checklist
- [ ] All pods healthy
- [ ] Metrics collecting
- [ ] Alerts configured
- [ ] Dashboards working
- [ ] Team notified

### Security Checklist
- [ ] TLS enabled for all communications
- [ ] RBAC configured in Kubernetes
- [ ] Secrets encrypted at rest
- [ ] Access to monitoring system is restricted

---

*Reviewer: Site Reliability Engineer*  
* Approved by: Engineering Manager, Security Team*  
* Completion Date: Expected 2025-02-14*