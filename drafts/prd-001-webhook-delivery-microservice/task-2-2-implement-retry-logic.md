# Task 2.2: Implement Retry Logic

**Task ID:** T2-002  
**Phase:** Phase 2 - Core Implementation  
**Duration:** 6 days  
**Assignee:** Backend Engineer  
**Priority:** Critical  

## Overview

This task involves implementing a robust retry mechanism for webhook deliveries that handles transient failures gracefully. The implementation will include exponential backoff, jitter, circuit breaker patterns, dead letter queue handling, and configurable retry policies. The retry logic will ensure high delivery reliability while preventing system overload.

## Prerequisites

- Core webhook service from Task 2.1 is complete
- Message queue infrastructure is operational
- Database schema includes retry tracking fields
- Retry policy requirements are defined
- Circuit breaker library selected

## Detailed Steps

### Step 1: Define Retry Policy Framework (Day 1)
1. Create retry policy configuration structure
2. Implement policy storage and retrieval
3. Design default and custom policies
4. Add policy validation

```go
// internal/model/policy.go
package model

import "time"

type RetryPolicy struct {
    ID             string    `gorm:"primaryKey;type:uuid" json:"id"`
    Name           string    `gorm:"not null;unique" json:"name"`
    Description    string    `json:"description"`
    MaxAttempts    int       `gorm:"not null" json:"maxAttempts"`
    BaseDelay      int       `gorm:"not null" json:"baseDelay"` // in milliseconds
    MaxDelay       int       `gorm:"not null" json:"maxDelay"`  // in milliseconds
    BackoffFactor  float64   `gorm:"not null" json:"backoffFactor"`
    JitterEnabled  bool      `gorm:"not null;default:true" json:"jitterEnabled"`
    JitterPercent  float64   `gorm:"not null;default:0.1" json:"jitterPercent"`
    RetryableCodes[]int     `gorm:"type:integer[]" json:"retryableCodes"`
    IsActive       bool      `gorm:"not null;default:true" json:"isActive"`
    CreatedAt      time.Time `gorm:"not null" json:"createdAt"`
    UpdatedAt      time.Time `gorm:"not null" json:"updatedAt"`
}

func (p *RetryPolicy) CalculateDelay(attempt int) time.Duration {
    if attempt <= 0 {
        return time.Duration(p.BaseDelay) * time.Millisecond
    }
    
    // Exponential backoff with jitter
    delay := float64(p.BaseDelay) * math.Pow(p.BackoffFactor, float64(attempt-1))
    
    if delay > float64(p.MaxDelay) {
        delay = float64(p.MaxDelay)
    }
    
    if p.JitterEnabled {
        // Add random jitter
        jitterRange := delay * p.JitterPercent
        jitter := (rand.Float64()*2-1) * jitterRange
        delay += jitter
    }
    
    return time.Duration(delay) * time.Millisecond
}

// Default retry policies
var DefaultPolicies = []*RetryPolicy{
    {
        ID:             "policy-default",
        Name:           "Default Policy",
        Description:    "Standard retry policy for most webhooks",
        MaxAttempts:    3,
        BaseDelay:      1000,  // 1 second
        MaxDelay:       30000, // 30 seconds
        BackoffFactor:  2.0,
        JitterEnabled:  true,
        JitterPercent:  0.1,
        RetryableCodes: []int{408, 429, 500, 502, 503, 504},
    },
    {
        ID:             "policy-aggressive",
        Name:           "Aggressive Policy",
        Description:    "High retry frequency for critical endpoints",
        MaxAttempts:    5,
        BaseDelay:      500,   // 500ms
        MaxDelay:       10000, // 10 seconds
        BackoffFactor:  1.5,
        JitterEnabled:  true,
        JitterPercent:  0.2,
        RetryableCodes: []int{408, 429, 500, 502, 503, 504, 521, 522, 523, 524},
    },
    {
        ID:             "policy-conservative",
        Name:           "Conservative Policy",
        Description:    "Limited retries for unreliable endpoints",
        MaxAttempts:    2,
        BaseDelay:      2000,  // 2 seconds
        MaxDelay:       60000, // 1 minute
        BackoffFactor:  3.0,
        JitterEnabled:  true,
        JitterPercent:  0.05,
        RetryableCodes: []int{500, 502, 503, 504},
    },
}
```

### Step 2: Implement Retry Engine (Day 2)
1. Create retry execution engine
2. Implement state machine for retry logic
3. Add retry decision logic
4. Track retry attempts and outcomes

```go
// internal/service/retry.go
package service

import (
    "context"
    "errors"
    "fmt"
    "math"
    "net/http"
    "time"
)

type RetryEngine interface {
    ShouldRetry(statusCode int, attempt int, policy *model.RetryPolicy) bool
    CalculateNextAttempt(attempt int, policy *model.RetryPolicy) time.Time
    ExecuteWithRetry(ctx context.Context, webhook *model.Webhook, policy *model.RetryPolicy) error
}

type retryEngine struct {
    webhookRepo repository.WebhookRepository
    queue       queue.Producer
    logger      logger.Logger
    metrics     metrics.Metrics
}

func NewRetryEngine(
    webhookRepo repository.WebhookRepository,
    queue queue.Producer,
    logger logger.Logger,
    metrics metrics.Metrics,
) RetryEngine {
    return &retryEngine{
        webhookRepo: webhookRepo,
        queue:       queue,
        logger:      logger,
        metrics:     metrics,
    }
}

func (r *retryEngine) ShouldRetry(statusCode int, attempt int, policy *model.RetryPolicy) bool {
    // Check max attempts
    if attempt >= policy.MaxAttempts {
        return false
    }
    
    // Check if status code is retryable
    for _, code := range policy.RetryableCodes {
        if statusCode == code {
            return true
        }
    }
    
    // Special cases
    switch statusCode {
    case 0: // Network error
        return true
    case http.StatusTooManyRequests:
        return true
    default:
        return false
    }
}

func (r *retryEngine) CalculateNextAttempt(attempt int, policy *model.RetryPolicy) time.Time {
    delay := policy.CalculateDelay(attempt)
    return time.Now().Add(delay)
}

func (r *retryEngine) ExecuteWithRetry(
    ctx context.Context,
    webhook *model.Webhook,
    policy *model.RetryPolicy,
) error {
    var lastError error
    
    for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
        attempt += 1 // 1-based attempts
        
        // Update webhook status
        webhook.Attempts = attempt
        if attempt > 1 {
            webhook.Status = model.StatusRetrying
        }
        webhook.UpdatedAt = time.Now()
        
        if err := r.webhookRepo.Update(ctx, webhook); err != nil {
            r.logger.Error("failed to update webhook before attempt",
                "webhookId", webhook.ID,
                "attempt", attempt,
                "error", err)
            // Continue with attempt anyway
        }
        
        // Attempt delivery
        err := r.attemptDelivery(ctx, webhook)
        lastError = err
        
        if err == nil {
            // Success!
            webhook.Status = model.StatusDelivered
            webhook.DeliveredAt = &time.Time{}
            *webhook.DeliveredAt = time.Now()
            webhook.LastError = ""
            
            if updateErr := r.webhookRepo.Update(ctx, webhook); updateErr != nil {
                r.logger.Error("failed to update webhook on success",
                    "webhookId", webhook.ID,
                    "error", updateErr)
            }
            
            r.metrics.IncrementWithTags("webhook.delivered", map[string]string{
                "attempt":  fmt.Sprintf("%d", attempt),
                "endpoint": webhook.EndpointID,
            })
            
            return nil
        }
        
        // Parse error to get status code
        statusCode := r.extractStatusCode(err)
        
        // Check if we should retry
        if !r.ShouldRetry(statusCode, attempt, policy) {
            webhook.Status = model.StatusFailed
            webhook.LastError = err.Error()
            
            if updateErr := r.webhookRepo.Update(ctx, webhook); updateErr != nil {
                r.logger.Error("failed to update webhook as failed",
                    "webhookId", webhook.ID,
                    "error", updateErr)
            }
            
            r.metrics.IncrementWithTags("webhook.failed", map[string]string{
                "attempt":     fmt.Sprintf("%d", attempt),
                "statusCode":  fmt.Sprintf("%d", statusCode),
                "endpoint":    webhook.EndpointID,
            })
            
            return fmt.Errorf("webhook delivery failed after %d attempts: %w", attempt, lastError)
        }
        
        // Log the error and prepare for retry
        webhook.LastError = err.Error()
        webhook.NextAttempt = &time.Time{}
        *webhook.NextAttempt = r.CalculateNextAttempt(attempt, policy)
        
        if updateErr := r.webhookRepo.Update(ctx, webhook); updateErr != nil {
            r.logger.Error("failed to update webhook for retry",
                "webhookId", webhook.ID,
                "attempt", attempt,
                "nextAttempt", webhook.NextAttempt,
                "error", updateErr)
        }
        
        r.logger.Info("webhook delivery attempt failed, scheduling retry",
            "webhookId", webhook.ID,
            "attempt", attempt,
            "statusCode", statusCode,
            "nextAttempt", webhook.NextAttempt,
            "error", err)
        
        r.metrics.IncrementWithTags("webhook.retry", map[string]string{
            "attempt":     fmt.Sprintf("%d", attempt),
            "statusCode":  fmt.Sprintf("%d", statusCode),
            "endpoint":    webhook.EndpointID,
        })
        
        // Schedule next attempt via queue
        if err := r.scheduleRetry(ctx, webhook.Id, *webhook.NextAttempt); err != nil {
            r.logger.Error("failed to schedule retry",
                "webhookId", webhook.ID,
                "error", err)
        }
        
        return fmt.Errorf("webhook delivery attempt %d failed: %w", attempt, err)
    }
    
    return fmt.Errorf("all retry attempts exhausted: %w", lastError)
}

func (r *retryEngine) scheduleRetry(ctx context.Context, webhookID string, nextAttempt time.Time) error {
    delay := time.Until(nextAttempt)
    if delay < 0 {
        delay = 0
    }
    
    // Send to delay queue
    return r.queue.PublishWithDelay(ctx, queue.RetryQueue, &queue.WebhookMessage{
        ID:       webhookID,
        Attempt:  1, // Will be set by consumer
        Priority: 0,
    }, delay)
}
```

### Step 3: Implement Circuit Breaker (Day 3)
1. Integrate circuit breaker library
2. Configure per-endpoint circuit breakers
3. Implement failure detection
4. Add automatic recovery

```go
// internal/circuitbreaker/breaker.go
package circuitbreaker

import (
    "sync"
    "time"
)

type CircuitBreaker interface {
    Call(fn func() error) error
    State() State
    Reset()
}

type State int

const (
    StateClosed State = iota
    StateHalfOpen
    StateOpen
)

type circuitBreaker struct {
    name           string
    maxFailures    int
    resetTimeout   time.Duration
    timeout        time.Duration
    
    mu          sync.RWMutex
    state       State
    failures    int
    lastFailure time.Time
    
    metrics Metrics
}

type Config struct {
    MaxFailures  int           `yaml:"maxFailures"`
    ResetTimeout time.Duration `yaml:"resetTimeout"`
    Timeout      time.Duration `yaml:"timeout"`
}

func NewCircuitBreaker(name string, config Config, metrics Metrics) CircuitBreaker {
    return &circuitBreaker{
        name:         name,
        maxFailures:  config.MaxFailures,
        resetTimeout: config.ResetTimeout,
        timeout:      config.Timeout,
        state:        StateClosed,
        metrics:      metrics,
    }
}

func (cb *circuitBreaker) Call(fn func() error) error {
    cb.mu.Lock()
    
    // Check state transitions
    switch cb.state {
    case StateOpen:
        if time.Since(cb.lastFailure) > cb.resetTimeout {
            cb.state = StateHalfOpen
            cb.metrics.Gauge("circuitbreaker.state", float64(StateHalfOpen), map[string]string{"name": cb.name})
        } else {
            cb.mu.Unlock()
            return ErrCircuitBreakerOpen
        }
    case StateHalfOpen:
        // Allow a single call through
    }
    
    cb.mu.Unlock()
    
    // Execute the function with timeout
    done := make(chan error, 1)
    go func() {
        done <- fn()
    }()
    
    var err error
    select {
    case err = <-done:
    case <-time.After(cb.timeout):
        err = ErrCircuitBreakerTimeout
        cb.recordFailure()
        return err
    }
    
    if err != nil {
        cb.recordFailure()
        return err
    }
    
    cb.recordSuccess()
    return nil
}

func (cb *circuitBreaker) recordFailure() {
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    cb.failures++
    cb.lastFailure = time.Now()
    
    if cb.state == StateHalfOpen || 
       (cb.state == StateClosed && cb.failures >= cb.maxFailures) {
        cb.state = StateOpen
        cb.metrics.Gauge("circuitbreaker.state", float64(StateOpen), map[string]string{"name": cb.name})
    }
    
    cb.metrics.Counter("circuitbreaker.failures", 1, map[string]string{"name": cb.name})
}

func (cb *circuitBreaker) recordSuccess() {
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    cb.failures = 0
    
    if cb.state == StateHalfOpen {
        cb.state = StateClosed
        cb.metrics.Gauge("circuitbreaker.state", float64(StateClosed), map[string]string{"name": cb.name})
    }
    
    cb.metrics.Counter("circuitbreaker.successes", 1, map[string]string{"name": cb.name})
}

func (cb *circuitBreaker) State() State {
    cb.mu.RLock()
    defer cb.mu.RUnlock()
    return cb.state
}

func (cb *circuitBreaker) Reset() {
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    cb.state = StateClosed
    cb.failures = 0
    cb.lastFailure = time.Time{}
    
    cb.metrics.Gauge("circuitbreaker.state", float64(StateClosed), map[string]string{"name": cb.name})
}

// Integration with delivery service
func (r *retryEngine) attemptDelivery(ctx context.Context, webhook *model.Webhook) error {
    // Get or create circuit breaker for endpoint
    breaker := r.getOrCreateBreaker(webhook.URL)
    
    // Execute delivery through circuit breaker
    return breaker.Call(func() error {
        return r.deliverToEndpoint(ctx, webhook)
    })
}

func (r *retryEngine) getOrCreateBreaker(url string) CircuitBreaker {
    r.mu.RLock()
    breaker, exists := r.breakers[url]
    r.mu.RUnlock()
    
    if !exists {
        r.mu.Lock()
        defer r.mu.Unlock()
        
        // Double-check
        if breaker, exists = r.breakers[url]; exists {
            return breaker
        }
        
        // Create new circuit breaker
        config := circuitbreaker.Config{
            MaxFailures:  5,
            ResetTimeout: 30 * time.Second,
            Timeout:      10 * time.Second,
        }
        
        breaker = circuitbreaker.NewCircuitBreaker(
            url,
            config,
            r.metrics.WithTags(map[string]string{"component": "circuitbreaker"}),
        )
        
        r.breakers[url] = breaker
    }
    
    return breaker
}
```

### Step 4: Implement Dead Letter Queue (Day 4)
1. Configure RabbitMQ DLX (Dead Letter Exchange)
2. Implement DLQ consumer
3. Add manual retry capability
4. Create DLQ management interface

```go
// internal/service/dlq.go
package service

import (
    "context"
    "encoding/json"
    "time"
)

type DLQService interface {
    ProcessDLQ(ctx context.Context) error
    RetryFromDLQ(ctx context.Context, webhookID string) error
    ListDLQMessages(ctx context.Context, limit, offset int) ([]*DLQMessage, error)
    PurgeDLQ(ctx context.Context, olderThan time.Time) error
}

type DLQMessage struct {
    ID          string            `json:"id"`
    Webhook     *model.Webhook    `json:"webhook"`
    OriginalMsg  string           `json:"original_message"`
    ErrorMsg    string           `json:"error_message"`
    Timestamp   time.Time        `json:"timestamp"`
    Metadata    map[string]string `json:"metadata"`
}

type dlqService struct {
    dlqConsumer queue.Consumer
    dlqProducer queue.Producer
    webhookRepo repository.WebhookRepository
    logger      logger.Logger
}

func NewDLQService(
    dlqConsumer queue.Consumer,
    dlqProducer queue.Producer,
    webhookRepo repository.WebhookRepository,
    logger logger.Logger,
) DLQService {
    return &dlqService{
        dlqConsumer: dlqConsumer,
        dlqProducer: dlqProducer,
        webhookRepo: webhookRepo,
        logger:      logger,
    }
}

func (s *dlqService) ProcessDLQ(ctx context.Context) error {
    messages, err := s.dlqConsumer.Consume(ctx, queue.DeadLetterQueue)
    if err != nil {
        return err
    }
    
    for msg := range messages {
        var deadMsg DLQMessage
        if err := json.Unmarshal(msg.Body, &deadMsg); err != nil {
            s.logger.Error("failed to unmarshal DLQ message", "error", err)
            msg.Ack(false)
            continue
        }
        
        // Update webhook status to dead
        webhook := deadMsg.Webhook
        webhook.Status = model.StatusDead
        webhook.LastError = "Moved to dead letter queue: " + deadMsg.ErrorMsg
        
        if err := s.webhookRepo.Update(ctx, webhook); err != nil {
            s.logger.Error("failed to update webhook as dead",
                "webhookId", webhook.ID,
                "error", err)
            msg.Nack(false, false) // Don't requeue
            continue
        }
        
        s.logger.Info("webhook moved to dead letter queue",
            "webhookId", webhook.ID,
            "error", deadMsg.ErrorMsg)
        
        msg.Ack(false)
    }
    
    return nil
}

func (s *dlqService) RetryFromDLQ(ctx context.Context, webhookID string) error {
    webhook, err := s.webhookRepo.GetByID(ctx, webhookID)
    if err != nil {
        return err
    }
    
    if webhook.Status != model.StatusDead {
        return errors.New("webhook is not in dead letter queue")
    }
    
    // Reset webhook for retry
    webhook.Status = model.StatusQueued
    webhook.Attempts = 0
    webhook.LastError = ""
    webhook.NextAttempt = nil
    webhook.UpdatedAt = time.Now()
    
    if err := s.webhookRepo.Update(ctx, webhook); err != nil {
        return err
    }
    
    // Re-queue webhook
    if err := s.dlqProducer.Publish(ctx, queue.WebhookQueue, &queue.WebhookMessage{
        ID:       webhookID,
        Attempt:  0,
        Priority: 0,
    }); err != nil {
        return err
    }
    
    s.logger.Info("webhook re-queued from dead letter queue",
        "webhookId", webhookID)
    
    return nil
}
```

### Step 5: Create Retry Scheduler (Day 5)
1. Implement periodic retry processor
2. Add concurrent retry workers
3. Implement retry rate limiting
4. Add retry priority handling

```go
// internal/service/scheduler.go
package service

import (
    "context"
    "sync"
    "time"
)

type RetryScheduler interface {
    Start(ctx context.Context) error
    Stop() error
    ProcessPendingRetries(ctx context.Context) error
}

type retryScheduler struct {
    webhookRepo  repository.WebhookRepository
    retryEngine  RetryEngine
    dlqService   DLQService
    workerCount  int
    pollInterval time.Duration
    logger       logger.Logger
    metrics      metrics.Metrics
    
    workers     []*retryWorker
    ctx         context.Context
    cancel      context.CancelFunc
    wg          sync.WaitGroup
}

type retryWorker struct {
    id           int
    scheduler    *retryScheduler
    retryQueue   chan string
    active       bool
}

func NewRetryScheduler(
    webhookRepo repository.WebhookRepository,
    retryEngine RetryEngine,
    dlqService DLQService,
    workerCount int,
    pollInterval time.Duration,
    logger logger.Logger,
    metrics metrics.Metrics,
) RetryScheduler {
    return &retryScheduler{
        webhookRepo:  webhookRepo,
        retryEngine:  retryEngine,
        dlqService:   dlqService,
        workerCount:  workerCount,
        pollInterval: pollInterval,
        logger:       logger,
        metrics:      metrics,
    }
}

func (s *retryScheduler) Start(ctx context.Context) error {
    s.ctx, s.cancel = context.WithCancel(ctx)
    
    // Initialize worker pool
    s.retryQueue = make(chan string, 1000)
    
    for i := 0; i < s.workerCount; i++ {
        worker := &retryWorker{
            id:         i,
            scheduler:  s,
            retryQueue: s.retryQueue,
            active:     false,
        }
        s.workers = append(s.workers, worker)
    }
    
    // Start workers
    for _, worker := range s.workers {
        s.wg.Add(1)
        go worker.run()
    }
    
    // Start periodic scanner
    s.wg.Add(1)
    go s.runScanner()
    
    s.logger.Info("retry scheduler started",
        "workerCount", s.workerCount,
        "pollInterval", s.pollInterval)
    
    return nil
}

func (s *retryScheduler) Stop() error {
    s.cancel()
    
    // Wait for all workers to finish
    done := make(chan struct{})
    go func() {
        s.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        s.logger.Info("retry scheduler stopped gracefully")
    case <-time.After(30 * time.Second):
        s.logger.Warn("retry scheduler stop timeout, forcing exit")
    }
    
    return nil
}

func (s *retryScheduler) ProcessPendingRetries(ctx context.Context) error {
    // Get webhooks ready for retry
    now := time.Now()
    webhooks, err := s.webhookRepo.GetPendingForRetry(ctx, now)
    if err != nil {
        return err
    }
    
    for _, webhook := range webhooks {
        select {
        case s.retryQueue <- webhook.ID:
            // Queued for processing
            s.metrics.Counter("retry.scheduled", 1, map[string]string{
                "endpoint": webhook.EndpointID,
            })
        default:
            // Queue is full, skip this webhook
            s.metrics.Counter("retry.dropped", 1)
            s.logger.Warn("retry queue full, dropping webhook",
                "webhookId", webhook.ID)
        }
    }
    
    return nil
}

func (s *retryScheduler) runScanner() {
    defer s.wg.Done()
    
    ticker := time.NewTicker(s.pollInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-s.ctx.Done():
            return
        case <-ticker.C:
            if err := s.ProcessPendingRetries(s.ctx); err != nil {
                s.logger.Error("error processing pending retries", "error", err)
            }
        }
    }
}

func (w *retryWorker) run() {
    defer w.scheduler.wg.Done()
    
    w.scheduler.logger.Debug("retry worker started", "workerId", w.id)
    w.active = true
    
    for {
        select {
        case <-w.scheduler.ctx.Done():
            w.scheduler.logger.Debug("retry worker stopped", "workerId", w.id)
            w.active = false
            return
            
        case webhookID := <-w.retryQueue:
            w.processWebhook(webhookID)
        }
    }
}

func (w *retryWorker) processWebhook(webhookID string) {
    start := time.Now()
    
    // Get webhook details
    webhook, err := w.scheduler.webhookRepo.GetByID(w.scheduler.ctx, webhookID)
    if err != nil {
        w.scheduler.logger.Error("failed to get webhook for retry",
            "webhookId", webhookID,
            "error", err)
        return
    }
    
    // Get retry policy
    policy := w.scheduler.getRetryPolicy(webhook)
    
    // Execute retry
    w.scheduler.metrics.Counter("retry.attempts", 1)
    
    if err := w.scheduler.retryEngine.ExecuteWithRetry(w.scheduler.ctx, webhook, policy); err != nil {
        w.scheduler.logger.Error("webhook retry failed",
            "webhookId", webhookID,
            "attempt", webhook.Attempts,
            "error", err)
        
        // If this was the final attempt, move to DLQ
        if webhook.Attempts >= policy.MaxAttempts {
            w.scheduler.metrics.Counter("retry.exhausted", 1)
            
            if dlqErr := w.scheduler.moveDLQ(webhook); dlqErr != nil {
                w.scheduler.logger.Error("failed to move webhook to DLQ",
                    "webhookId", webhookID,
                    "error", dlqErr)
            }
        }
    } else {
        w.scheduler.metrics.Counter("retry.success", 1)
    }
    
    duration := time.Since(start)
    w.scheduler.metrics.Histogram("retry.duration", duration.Seconds())
}
```

### Step 6: Add Monitoring and Metrics (Day 6)
1. Create retry-specific metrics
2. Add alerting rules
3. Implement retry dashboard
4. Add retry analytics

```go
// internal/metrics/retry.go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
 retryAttempts = prometheus.NewCounterVec(
     prometheus.CounterOpts{
         Name: "webhook_retry_attempts_total",
         Help: "Total number of retry attempts",
     },
     []string{"endpoint", "attempt"},
 )
 
 retrySuccesses = prometheus.NewCounterVec(
     prometheus.CounterOpts{
         Name: "webhook_retry_successes_total",
         Help: "Total number of successful retries",
     },
     []string{"endpoint", "attempt"},
 )
 
 retryExhausted = prometheus.NewCounterVec(
     prometheus.CounterOpts{
         Name: "webhook_retry_exhausted_total",
         Help: "Total number of exhausted retries (moved to DLQ)",
     },
     []string{"endpoint", "policy"},
 )
 
 retryDelay = prometheus.NewHistogramVec(
     prometheus.HistogramOpts{
         Name:    "webhook_retry_delay_seconds",
         Help:    "Delay between retry attempts",
         Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
     },
     []string{"endpoint", "attempt"},
 )
 
 circuitBreakerState = prometheus.NewGaugeVec(
     prometheus.GaugeOpts{
         Name: "webhook_circuitbreaker_state",
         Help: "Circuit breaker state (0=closed, 1=half-open, 2=open)",
     },
     []string{"endpoint"},
 )
)

func init() {
    prometheus.MustRegister(retryAttempts)
    prometheus.MustRegister(retrySuccesses)
    prometheus.MustRegister(retryExhausted)
    prometheus.MustRegister(retryDelay)
    prometheus.MustRegister(circuitBreakerState)
}
```

## Acceptance Criteria

### Must-Have
- [ ] Exponential backoff implemented correctly
- [ ] Configurable retry policies saved and applied
- [ ] Circuit breaker prevents cascade failures
- [ ] Dead letter queue captures failed webhooks
- [ ] Manual retry from DLQ works
- [ ] All retry attempts logged

### Should-Have
- [ ] Jitter prevents thundering herd
- [ ] Circuit breaker auto-recovery works
- [ ] Retry dashboard shows metrics
- [ ] Rate limiting prevents overwhelming endpoints
- [ ] Priority queuing for critical webhooks

### Could-Have
- [ ] Machine learning for retry optimization
- [ ] Adaptive backoff based on endpoint behavior
- [ ] Batch retry capability
- [ ] Webhook delivery correlation tracking

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Retry processing latency | < 10ms | Per webhook |
| DLQ processing throughput | 1000/min | Sustained |
| Circuit breaker detection | < 100ms | Failure detection |
| Scheduler poll interval | 10s | Configurable |

## Testing Requirements

1. **Unit Tests**
   - Retry policy calculation accuracy
   - Circuit breaker state transitions
   - DLQ message handling

2. **Integration Tests**
   - End-to-end retry flows
   - Circuit breaker with real endpoints
   - DLQ retry workflow

3. **Chaos Tests**
   - Network failures
   - Endpoint downtime
   - Queue unavailability

## Deliverables

1. **Source Code**
   - Retry engine implementation
   - Circuit breaker integration
   - DLQ service
   - Retry scheduler

2. **Configuration**
   - Default retry policies
   - Circuit breaker thresholds
   - Scheduler settings

3. **Monitoring**
   - Retry metrics dashboard
   - Circuit breaker alerts
   - DLQ monitoring

---

## Checklists

### Code Review Checklist
- [ ] All retry paths tested
- [ ] Circuit breaker thresholds reasonable
- [ ] DLQ processing robust
- [ ] Metrics comprehensive
- [ ] Error messages clear

### Integration Checklist
- [ ] Works with webhook service
- [ ] Queue bindings correct
- [ ] Database updates atomic
- [ ] Monitoring data accurate

---

*Reviewer: Senior Backend Engineer*  
* Approved by: Tech Lead, SRE Team*  
* Completion Date: Expected 2025-03-03*