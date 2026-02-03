# Task 3.2: Performance Testing

**Task ID:** T3-002  
**Phase:** Phase 3 - Testing & Deployment  
**Duration:** 5 days  
**Assignee:** Performance Engineer  
**Priority:** Critical  

## Overview

This task involves comprehensive performance testing of the Webhook Delivery Microservice to ensure it meets all performance requirements under various load conditions. The testing will validate throughput, latency, scalability, and resource utilization. We'll use k6 for load testing, Grafana k6 for visualization, and custom scripts for specific scenarios.

## Prerequisites

- Service deployed in staging environment
- Monitoring dashboards operational
- Test data populated
- Performance baselines established
- Load testing tools configured

## Detailed Steps

### Step 1: Performance Testing Strategy (Day 1)
1. Define performance test scenarios
2. Establish performance baselines
3. Configure test environments
4. Set up monitoring tools
5. Create test data generators

```javascript
// k6/performance-test.js
import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Counter } from 'k6/metrics';
import { randomIntBetween, randomItem } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
export let webhookSuccessRate = new Rate('webhook_success_rate');
export let webhookLatency = new Rate('webhook_latency');
export let webhookErrors = new Counter('webhook_errors');

// Test configuration
export let options = {
    stages: [
        { duration: '2m', target: 100 },   // Ramp up
        { duration: '5m', target: 100 },   // Stay at 100
        { duration: '2m', target: 500 },   // Ramp up to 500
        { duration: '5m', target: 500 },   // Stay at 500
        { duration: '2m', target: 1000 },  // Ramp up to 1000
        { duration: '5m', target: 1000 },  // Stay at 1000
        { duration: '2m', target: 2000 },  // Ramp up to 2000
        { duration: '5m', target: 2000 },  // Stay at 2000
        { duration: '2m', target: 0 },     // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<1000'],
        http_req_failed: ['rate<0.01'],
        webhook_success_rate: ['rate>0.99'],
    },
};

// Test data
const endpoints = [
    'https://webhook.site/endpoint1',
    'https://webhook.site/endpoint2',
    'https://webhook.site/endpoint3',
    'https://webhook.site/endpoint4',
    'https://webhook.site/endpoint5',
];

const payloads = {
    'user.created': { userId: randomIntBetween(1000, 9999), email: 'test@example.com' },
    'order.completed': { orderId: uuidv4(), amount: randomIntBetween(10, 1000) },
    'payment.failed': { paymentId: uuidv4(), reason: randomItem(['insufficient_funds', 'card_declined']) },
};

export function setup() {
    // Initialize test data
    console.log('Setting up performance test...');
    
    // Create test endpoints
    for (let endpoint of endpoints) {
        let response = http.post(`${__ENV.BASE_URL}/api/v1/endpoints`, JSON.stringify({
            name: `Test Endpoint ${endpoint}`,
            url: endpoint,
            secretKey: 'test-secret',
            algorithm: 'sha256',
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${__ENV.API_TOKEN}`,
            },
        });
        
        check(response, {
            'endpoint created': (r) => r.status === 200,
        });
    }
    
    console.log('Setup complete');
}

export default function() {
    group('Webhook Submission', function() {
        let payload = randomItem(Object.values(payloads));
        let eventType = Object.keys(payloads).find(key => payloads[key] === payload);
        
        let webhookPayload = {
            url: randomItem(endpoints),
            method: 'POST',
            payload: {
                event: eventType,
                ...payload,
                timestamp: new Date().toISOString(),
            },
            headers: {
                'Content-Type': 'application/json',
                'X-Event-Type': eventType,
            },
        };
        
        let response = http.post(`${__ENV.BASE_URL}/api/v1/webhooks`, JSON.stringify(webhookPayload), {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${__ENV.API_TOKEN}`,
            },
        });
        
        let success = check(response, {
            'status is 202': (r) => r.status === 202,
            'response time < 100ms': (r) => r.timings.duration < 100,
            'has webhook ID': (r) => JSON.parse(r.body).id !== undefined,
        });
        
        if (success) {
            webhookSuccessRate.add(1);
        } else {
            webhookErrors.add(1);
        }
        
        webhookLatency.add(response.timings.duration);
    });
    
    group('Webhook Status Check', function() {
        // Sample 10% of requests for status check
        if (Math.random() < 0.1) {
            let response = http.get(`${__ENV.BASE_URL}/api/v1/webhooks/random-id/status`, {
                headers: {
                    'Authorization': `Bearer ${__ENV.API_TOKEN}`,
                },
            });
            
            check(response, {
                'status request handled': (r) => r.status === 200 || r.status === 404,
            });
        }
    });
    
    sleep(randomIntBetween(0.1, 0.5));
}

export function teardown() {
    console.log('Cleaning up test data...');
    
    // Remove test endpoints
    for (let endpoint of endpoints) {
        // Implementation for cleanup
    }
    
    console.log('Teardown complete');
}

function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        let r = Math.random() * 16 | 0;
        let v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}
```

### Step 2: Baseline Performance Testing (Day 2)
1. Run single-user baseline tests
2. Measure individual endpoint performance
3. Record resource utilization
4. Document baseline metrics
5. Identify bottlenecks

```bash
#!/bin/bash
# scripts/run-baseline.sh

echo "Running baseline performance tests..."

# Single user test
k6 run \
    --vus 1 \
    --duration 5m \
    --out json=baseline-single.json \
    k6/single-user-test.js

# Small load test (10 users)
k6 run \
    --vus 10 \
    --duration 5m \
    --out json=baseline-small.json \
    k6/small-load-test.js

# Resource utilization monitoring
kubectl top pods -n webhook-service --watch &
TOP_PID=$!

# Database performance monitoring
kubectl exec -it postgres-primary -n database -- \
  psql -U test -d webhook_test -c "SELECT * FROM pg_stat_activity;" > baseline-db-$(date +%s).txt

# Wait for tests to complete
wait $TOP_PID

echo "Baseline tests complete"
```

```python
# tests/performance/benchmark.py
import asyncio
import aiohttp
import time
import statistics
from typing import List, Dict, Any

class WebhookBenchmarker:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url
        self.api_token = api_token
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={'Authorization': f'Bearer {self.api_token}'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def measure_submission_latency(self, iterations: int = 100) -> Dict[str, Any]:
        latencies = []
        
        for i in range(iterations):
            payload = {
                "url": "https://httpbin.org/post",
                "method": "POST",
                "payload": {"test": "data", "iteration": i}
            }
            
            start_time = time.perf_counter()
            async with self.session.post(
                f"{self.base_url}/api/v1/webhooks",
                json=payload
            ) as response:
                await response.text()
            end_time = time.perf_counter()
            
            latencies.append((end_time - start_time) * 1000)  # Convert to ms
            
        return {
            'mean': statistics.mean(latencies),
            'median': statistics.median(latencies),
            'p95': statistics.quantiles(latencies, n=20)[18],
            'p99': statistics.quantiles(latencies, n=100)[98],
            'min': min(latencies),
            'max': max(latencies)
        }

async def main():
    async with WebhookBenchmarker(
        base_url="http://webhook-service.staging.svc.cluster.local:8080",
        api_token="test-token"
    ) as benchmarker:
        
        # Measure submission latency
        latency_stats = await benchmarker.measure_submission_latency(1000)
        
        print(f"Latency Statistics:")
        print(f"  Mean: {latency_stats['mean']:.2f}ms")
        print(f"  Median: {latency_stats['median']:.2f}ms")
        print(f"  P95: {latency_stats['p95']:.2f}ms")
        print(f"  P99: {latency_stats['p99']:.2f}ms")
        print(f"  Min: {latency_stats['min']:.2f}ms")
        print(f"  Max: {latency_stats['max']:.2f}ms")

if __name__ == "__main__":
    asyncio.run(main())
```

### Step 3: Load Testing (Days 2-3)
1. Increasing load tests (ramp-up scenarios)
2. Sustained load tests
3. Peak load tests
4. Stress testing to find breaking point
5. Resource exhaustion tests

```javascript
// k6/load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics for detailed analysis
export let submitRate = new Rate('submit_rate');
exportlet submitLatency = new Trend('submit_latency');
export let queueDepth = new Trend('queue_depth');

export let options = {
    scenarios: {
        constant_load: {
            executor: 'constant-vus',
            vus: 500,
            duration: '10m',
            exec: 'submitWebhook',
        },
        ramp_up_load: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 100 },
                { duration: '5m', target: 500 },
                { duration: '10m', target: 1000 },
                { duration: '5m', target: 500 },
                { duration: '2m', target: 0 },
            ],
            exec: 'submitWebhook',
        },
        spike_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '1m', target: 100 },
                { duration: '1m', target: 1000 },
                { duration: '1m', target: 100 },
                { duration: '1m', target: 2000 },
                { duration: '1m', target: 0 },
            ],
            exec: 'submitWebhook',
        },
    },
    thresholds: {
        'submit_rate': ['rate>0.95'],
        'submit_latency': ['p(95)<200'],
        'http_req_duration': ['p(99)<1000'],
    },
};

const ENDPOINTS = [
    'https://httpbin.org/post',
    'https://httpbin.org/status-200',
    'https://httpbin.org/post',
];

export function submitWebhook() {
    const payload = {
        url: ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)],
        method: 'POST',
        payload: {
            timestamp: new Date().toISOString(),
            loadTestId: __VU,
            iteration: __ITER,
        },
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const startTime = new Date().getTime();
    const response = http.post(
        `${__ENV.BASE_URL}/api/v1/webhooks`,
        JSON.stringify(payload),
        {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${__ENV.API_TOKEN}`,
            },
        }
    );
    const endTime = new Date().getTime();
    
    const success = check(response, {
        'status is 202': (r) => r.status === 202,
        'response time < 100ms': (r) => r.timings.duration < 100,
        'has webhook ID': (r) => JSON.parse(r.body).id !== undefined,
    });
    
    submitRate.add(success);
    submitLatency.add(endTime - startTime);
    
    // Check queue depth
    const queueResponse = http.get(
        `${__ENV.BASE_URL}/api/v1/admin/queue/depth`,
        {
            headers: {
                'Authorization': `Bearer ${__ENV.ADMIN_TOKEN}`,
            },
        }
    );
    
    if (queueResponse.status === 200) {
        const queueData = JSON.parse(queueResponse.body);
        queueDepth.add(queueData.depth);
    }
    
    sleep(randomIntBetween(0.05, 0.5));
}
```

### Step 4: Scalability Testing (Day 3-4)
1. Horizontal scaling tests
2. Auto-scaling validation
3. Database scaling performance
4. Queue scaling tests
5. Load balancing efficiency

```bash
#!/bin/bash
# scripts/scalability-test.sh

# Test horizontal scaling
test_horizontal_scaling() {
    echo "Testing horizontal scaling..."
    
    # Start with 1 replica
    kubectl scale deployment webhook-service --replicas=1 -n webhook-service
    sleep 30
    
    # Run baseline
    k6 run --vus 100 --duration 2m k6/scaling-test.js > results/scale-1x.json
    
    # Scale to 3 replicas
    kubectl scale deployment webhook-service --replicas=3 -n webhook-service
    sleep 60
    
    # Run same load
    k6 run --vus 100 --duration 2m k6/scaling-test.js > results/scale-3x.json
    
    # Scale to 5 replicas
    kubectl scale deployment webhook-service --replicas=5 -n webhook-service
    sleep 60
    
    # Run same load
    k6 run --vus 100 --duration 2m k6/scaling-test.js > results/scale-5x.json
    
    # Analyze results
    python scripts/analyze_scaling.py results/scale-*.json
}

# Test auto-scaling
test_auto_scaling() {
    echo "Testing auto-scaling..."
    
    # Configure HPA
    kubectl apply -f manifests/hpa.yaml
    
    # Monitor during load test
    kubectl get hpa webhook-service-hpa -n webhook-service -w &
    HPA_PID=$!
    
    # Run increasing load
    k6 run k6/auto-scaling-test.js
    
    kill $HPA_PID
}

# Run all scaling tests
main() {
    mkdir -p results
    
    test_horizontal_scaling
    test_auto_scaling
    
    echo "Scalability tests complete. Check results/ directory for output."
}

main "$@"
```

### Step 5: Resource Utilization Analysis (Day 4-5)
1. Monitor CPU/Memory usage
2. Database query performance
3. Network I/O analysis
4. Storage performance tests
5. Resource optimization recommendations

```yaml
# k6/monitoring-test.js
import exec from 'k6/x/exec';
import { check } from 'k6';

export let options = {
    vus: 100,
    duration: '5m',
};

export default function() {
    // Get pod resource usage
    let { stdout: podMetrics } = exec.command("kubectl top pods -n webhook-service --no-headers");
    let pods = podMetrics.split('\n');
    
    for (let pod of pods) {
        if (pod.trim() === '') continue;
        
        let [name, cpu, memory] = pod.trim().split(/\s+/);
        let cpuCores = parseCpu(cpu);
        let memoryMB = parseMemory(memory);
        
        check({
            'CPU usage < 0.5 cores': cpuCores < 0.5,
            'Memory usage < 512MB': memoryMB < 512,
        }, {
            'pod': name,
            'cpu': cpuCores,
            'memory': memoryMB,
        });
    }
    
    // Check database connections
    let { stdout: dbConn } = exec.command(
        `kubectl exec -it postgres-primary -n database -- psql -U test -d webhook_test -t -c "SELECT count(*) FROM pg_stat_activity WHERE datname='webhook_test';"`
    );
    let connections = parseInt(dbConn.trim());
    
    check({
        'DB connections < 80': connections < 80,
    }, {
        'connections': connections,
    });
    
    // Check queue depth
    let { stdout: queueDepth } = exec.command(
        `kubectl exec -it rabbitmq-0 -n message-queue -- rabbitmqctl list_queues name messages | grep webhook-queue`
    );
    let depth = parseInt(queueDepth.split(/\s+/)[1]);
    
    check({
        'Queue depth < 1000': depth < 1000,
    }, {
        'depth': depth,
    });
}

function parseCpu(cpuStr) {
    if (cpuStr.endsWith('m')) {
        return parseInt(cpuStr) / 1000;
    }
    return parseInt(cpuStr);
}

function parseMemory(memStr) {
    if (memStr.endsWith('Mi')) {
        return parseInt(memStr);
    }
    if (memStr.endsWith('Gi')) {
        return parseInt(memStr) * 1024;
    }
    return parseInt(memStr);
}
```

```python
# scripts/analyze_performance.py
import json
import sys
import statistics
from pathlib import Path
from typing import Dict, List, Any

class PerformanceAnalyzer:
    def __init__(self):
        self.results = {}
    
    def load_k6_result(self, filepath: Path) -> Dict[str, Any]:
        """Load k6 JSON results"""
        with open(filepath) as f:
            data = json.load(f)
        
        # Extract metrics
        metrics = data.get('metrics', {})
        http_reqs = metrics.get('http_reqs')
        http_req_duration = metrics.get('http_req_duration')
        
        return {
            'total_requests': http_reqs['count'] if http_reqs else 0,
            'failed_requests': http_reqs['counters']['http_req_failed']['value'] if http_reqs else 0,
            'avg_duration': http_req_duration['avg'] if http_req_duration else 0,
            'p95_duration': http_req_duration['p(95)'] if http_req_duration else 0,
            'p99_duration': http_req_duration['p(99)'] if http_req_duration else 0,
            'rps': http_reqs['rate'] if http_reqs else 0,
        }
    
    def analyze_scalability(self, files: List[Path]):
        """Analyze horizontal scaling results"""
        print("Horizontal Scaling Analysis")
        print("=" * 50)
        
        results = []
        for f in files:
            scale = f.stem.split('-')[-1]  # Extract scale from filename
            metrics = self.load_k6_result(f)
            results.append((scale, metrics))
        
        print(f"{'Scale':<10} {'RPS':<10} {'Avg Latency':<15} {'P95 Latency':<15}")
        print("-" * 50)
        
        for scale, metrics in sorted(results):
            print(f"{scale:<10} {metrics['rps']:<10.2f} {metrics['avg_duration']:<15.2f} {metrics['p95_duration']:<15.2f}")
    
    def generate_report(self, filepath: Path) -> str:
        """Generate performance report"""
        metrics = self.load_k6_result(filepath)
        
        report = f"""
Performance Test Report
======================

Test Summary:
- Total Requests: {metrics['total_requests']}
- Failed Requests: {metrics['failed_requests']}
- Success Rate: {((metrics['total_requests'] - metrics['failed_requests']) / metrics['total_requests'] * 100):.2f}%
- Requests per Second: {metrics['rps']:.2f}

Latency Metrics:
- Average: {metrics['avg_duration']:.2f}ms
- 95th Percentile: {metrics['p95_duration']:.2f}ms
- 99th Percentile: {metrics['p99_duration']:.2f}ms

Recommendations:
"""
        
        if metrics['p95_duration'] > 500:
            report += "- P95 latency exceeds 500ms. Consider optimization.\n"
        
        if metrics['rps'] < 1000:
            report += "- RPS below target. Check for bottlenecks.\n"
        
        return report

def main():
    analyzer = PerformanceAnalyzer()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--scaling':
            files = [Path(f) for f in sys.argv[2:]]
            analyzer.analyze_scalability(files)
        else:
            result_file = Path(sys.argv[1])
            report = analyzer.generate_report(result_file)
            print(report)
    else:
        print("Usage: python analyze_performance.py [--scaling] result.json [result2.json ...]")

if __name__ == "__main__":
    main()
```

## Performance Targets

### Primary Metrics
| Metric | Target | Measurement | Status |
|--------|--------|-------------|--------|
| Throughput | 10,000 webhooks/min | API endpoint | TBD |
| Queue Latency | < 10ms | Message queue | TBD |
| Delivery Latency | < 500ms (p95) | End-to-end | TBD |
| API Request Latency | < 100ms | Submission API | TBD |
| Success Rate | > 99.9% | Delivery success | TBD |

### Resource Utilization
| Resource | Target | Limit | Alert |
|----------|--------|-------|-------|
| CPU per pod | < 70% | 90% | > 85% |
| Memory per pod | < 512MB | 1GB | > 950MB |
| Database connections | < 80 | 100 | > 90 |
| Queue depth | < 1,000 | 10,000 | > 5,000 |

## Test Environments

### Staging Environment
- **Configuration**: Same as production
- **Scale**: 1/4 of production capacity
- **Monitoring**: Full monitoring enabled
- **Data**: Realistic test data

### Load Testing Environment
- **Configuration**: Optimized for testing
- **Scale**: Variable based on test
- **Isolation**: Separate from production
- **Tools**: k6, JMeter, custom scripts

## Acceptance Criteria

### Must-Have
- [ ] All performance targets met or exceeded
- [ ] System handles 10,000 concurrent webhooks
- [ ] No memory leaks during sustained load
- [ ] Auto-scaling functions correctly
- [ ] Database queries optimized

### Should-Have
- [ ] Graceful degradation under extreme load
- [ ] Resource usage within limits
- [ ] No single points of failure
- [ ] Backpressure mechanisms working
- [ ] Efficient queue processing

### Could-Have
- [ ] Load predictive capabilities
- [ ] Automatic performance tuning
- [ ] Real-time scaling decisions
- [ ] Performance profiling tools

## Performance Monitoring

### Key Metrics Dashboard
```yaml
# grafana/performance-dashboard.json
{
  "dashboard": {
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P99"
          }
        ]
      },
      {
        "title": "Queue Depth",
        "targets": [
          {
            "expr": "rabbitmq_queue_bytes{queue=\"webhook-queue\"}",
            "legendFormat": "Queue Depth"
          }
        ]
      }
    ]
  }
}
```

## Deliverables

1. **Performance Test Reports**
   - Baseline performance metrics
   - Load test results
   - Scalability analysis
   - Performance recommendations

2. **Monitoring Dashboards**
   - Performance metrics visualization
   - Alert configurations
   - Capacity planning views
   - Resource utilization charts

3. **Automation Scripts**
   - k6 test scripts
   - Analysis tools
   - Report generators
   - CI/CD integration

4. **Documentation**
   - Performance testing guide
   - Troubleshooting manual
   - Capacity planning document
   - Optimization recommendations

---

## Checklists

### Pre-Test Checklist
- [ ] Test environment ready
- [ ] Monitoring tools configured
- [ ] Test data prepared
- [ ] Baselines established
- [ ] Alert thresholds set

### Post-Test Checklist
- [ ] Results analyzed
- [ ] Issues documented
- [ ] Recommendations created
- [ ] Stakeholders notified
- [ ] Follow-up actions defined

---

*Reviewer: Performance Engineer, SRE Team*  
* Approved by: Engineering Manager, DevOps Lead*  
* Completion Date: Expected 2025-03-29*