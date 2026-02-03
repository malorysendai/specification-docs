# Task 1.1: Provision Infrastructure

**Task ID:** T1-001  
**Phase:** Phase 1 - Infrastructure Setup  
**Duration:** 5 days  
**Assignee:** DevOps Engineer  
**Priority:** Critical  

## Overview

This task involves provisioning all necessary cloud infrastructure for the Webhook Delivery Microservice. This includes setting up the VPC network, Kubernetes cluster, databases, message queue, and all supporting services. All infrastructure will be defined as code (IaC) using Terraform to ensure reproducibility and version control.

## Prerequisites

- Cloud provider console access with administrative privileges
- Terraform >= 1.5 installed locally
- AWS/GCP/Azure CLI configured with appropriate credentials
- Network CIDR blocks approved by network team
- Cost center and billing codes assigned

## Detailed Steps

### Step 1: Network Setup (Day 1)
1. Create VPC with approved CIDR range (10.0.0.0/16)
2. Configure subnets across 3 availability zones:
   - Public subnets: 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24
   - Private subnets: 10.0.11.0/24, 10.0.12.0/24, 10.0.13.0/24
3. Set up NAT gateways for outbound internet access
4. Configure route tables and network ACLs
5. Create security group templates

```hcl
# VPC Configuration
resource "aws_vpc" "webhook_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "webhook-delivery-vpc"
    Environment = var.environment
    Project     = "webhook-delivery"
  }
}

# Subnets
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.webhook_vpc.id
  cidr_block        = "10.0.${11 + count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name        = "webhook-private-${count.index + 1}"
    Type        = "private"
    Environment = var.environment
  }
}
```

### Step 2: Kubernetes Cluster (Day 2)
1. Deploy EKS/GKE/AKS cluster (3 nodes initially)
2. Configure node groups:
   - System nodes: t3.medium (3 nodes, 1 per AZ)
   - Application nodes: t3.large (3 nodes, 1 per AZ)
   - Spot instances for batch workloads
3. Set up auto-scaling policies
4. Configure storage classes (gp3, io1)
5. Install cluster addons (ingress, metrics, etc.)

### Step 3: Database Setup (Day 3)
1. Create PostgreSQL RDS instance:
   - Instance class: db.r5.large
   - Multi-AZ deployment
   - Storage: 100GB gp3, auto-scaling to 1TB
   - Backup retention: 30 days
   - Maintenance window: Sunday 02:00-04:00 UTC
2. Configure parameter groups
3. Set up read replicas (2)
4. Enable Performance Insights
5. Create initial databases and users

```hcl
resource "aws_db_instance" "webhook_db" {
  identifier = "webhook-delivery-db"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r5.large"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type          = "gp3"
  storage_encrypted     = true
  
  db_name  = "webhook_deliver"
  username = var.db_username
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.webhook.name
  
  multi_az = true
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:02:00-sun:04:00"
  
  skip_final_snapshot = true
  
  tags = {
    Environment = var.environment
    Project     = "webhook-delivery"
  }
}
```

### Step 4: Message Queue (Day 4)
1. Deploy RabbitMQ cluster:
   - 3 nodes m5.large
   - Quorum queues for reliability
   - Persistent storage
   - Management UI
2. Configure exchanges and queues
3. Set up federation/shovel policies
4. Enable monitoring integrations
5. Test message persistence

### Step 5: Supporting Services (Day 5)
1. Redis cache (cluster mode enabled)
2. Load balancer configuration
3. SSL certificates via ACM
4. DNS records
5. Monitoring endpoints access

## Acceptance Criteria

### Must-Have
- [ ] All Terraform code committed and reviewed
- [ ] Infrastructure successfully provisioned in sandbox
- [ ] All resources tagged according to standards
- [ ] VPC peering established with existing infrastructure
- [ ] Kubernetes cluster healthy (all nodes ready)
- [ ] Database accessible with encrypted connections
- [ ] Message queue operational with HA mode

### Should-Have
- [ ] Infrastructure costs within approved budget
- [ ] Auto-scaling policies tested
- [ ] Backup schedules verified
- [ ] High availability tests passing
- [ ] Performance baselines recorded

### Could-Have
- [ ] Additional regions configured
- [ ] Cross-zone replication tested
- [ ] Infrastructure as code modules published
- [ ] Compliance scans passing

## Risk Mitigation

### High Risk
- **Resource Limits**: Check service quotas before provisioning
  - Mitigation: Request quota increases 48 hours in advance
  
### Medium Risk
- **Configuration Drift**: Use Terraform Cloud with state locking
  - Mitigation: Enable drift detection in CI/CD
  
### Low Risk
- **Cost Overrun**: Set up budget alerts at 80% and 95%
  - Mitigation: Daily cost reviews during provisioning

## Testing Requirements

1. Infrastructure validation tests
2. Network connectivity tests
3. Database failover tests
4. Queue high availability tests
5. Kubernetes cluster resilience tests

```bash
# Terraform validation
terraform fmt -check
terraform validate
terraform plan

# Health checks
kubectl get nodes
aws rds describe-db-instances
rabbitmqctl cluster_status
```

## Deliverables

1. **Infrastructure as Code Repository**
   - Terraform modules
   - Environment configuration files
   - Variable definitions
   - Output documentation

2. **Infrastructure Diagram**
   - Architecture diagram (draw.io)
   - Network topology
   - Data flow visualization

3. **Runbook**
   - Provisioning steps
   - Troubleshooting guide
   - Emergency procedures

4. **Cost Report**
   - Resource cost breakdown
   - Monthly projections
   - Optimization recommendations

## Estimated Costs

| Resource | Monthly Cost | Notes |
|----------|--------------|-------|
| VPC & Networking | $200 | Data transfer, NAT Gateways |
| Kubernetes Cluster | $1,200 | 6 m5.large nodes |
| PostgreSQL RDS | $800 | db.r5.large multi-AZ |
| RabbitMQ | $600 | 3 m5.large instances |
| Redis | $400 | Cache cluster |
| Load Balancer | $250 | ALB with HTTPS |
| Total | $3,450 | Estimated |

## Next Steps

Upon completion:
1. Run comprehensive infrastructure tests
2. Hand off to monitoring setup team
3. Begin CI/CD pipeline configuration
4. Update architecture documentation

---

## Checklists

### Pre-Execution Checklist
- [ ] Access and permissions verified
- [ ] Terraform version compatibility confirmed
- [ ] Cost center approved
- [ ] Network CIDRs confirmed
- [ ] Backup strategy reviewed

### Post-Execution Checklist
- [ ] Terraform state backed up
- [ ] All resources tagged
- [ ] Documentation created
- [ ] Tests executed and passed
- [ ] Handoff completed

### Security Review
- [ ] IAM principle of least privilege
- [ ] Security groups minimal access
- [ ] Encryption at rest enabled
- [ ] Encryption in transit enabled
- [ ] Access logging configured

---

*Reviewer: Infrastructure Lead*  
* Approved by: Security Team, Engineering Manager*  
* Completion Date: Expected 2025-02-07*