# Task 2.1: Build Webhook Service

**Task ID:** T2-001  
**Phase:** Phase 2 - Core Implementation  
**Duration:** 8 days  
**Assignee:** Backend Engineer  
**Priority:** Critical  

## Overview

This task involves building the core webhook delivery service that will handle webhook submissions, queue them for processing, and manage their delivery lifecycle. The service will be implemented in Go for performance and will follow microservices best practices with proper separation of concerns, dependency injection, and comprehensive error handling.

## Prerequisites

- Go 1.21+ installed
- Access to PostgreSQL database (from Task 1.1)
- Message queue (RabbitMQ) connection details
- Redis connection information
- Database schema design approved
- API contract finalized

## Detailed Steps

### Step 1: Project Setup (Day 1)
1. Initialize Go module and project structure
2. Configure dependency management (go.mod)
3. Set up development environment with Docker Compose
4. Initialize git repository with proper .gitignore
5. Create Makefile for common commands

```bash
# Project structure
webhook-service/
├── cmd/
│   └── service/
│       └── main.go
├── internal/
│   ├── config/
│   ├── repository/
│   ├── service/
│   ├── handler/
│   ├── model/
│   └── middleware/
├── pkg/
│   ├── errors/
│   └── logger/
├── migrations/
├── scripts/
├── tests/
├── docker/
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

### Step 2: Configuration Management (Day 1)
1. Implement configuration structure
2. Load from environment variables
3. Support for multiple environments
4. Validate configuration at startup

```go
// internal/config/config.go
package config

import (
    "time"
)

type Config struct {
    Server      ServerConfig      `yaml:"server"`
    Database    DatabaseConfig    `yaml:"database"`
    Redis       RedisConfig       `yaml:"redis"`
    RabbitMQ    RabbitMQConfig    `yaml:"rabbitmq"`
    Webhook     WebhookConfig     `yaml:"webhook"`
    Monitoring  MonitoringConfig  `yaml:"monitoring"`
}

type ServerConfig struct {
    Host         string        `yaml:"host" env:"SERVER_HOST" envDefault:"0.0.0.0"`
    Port         int           `yaml:"port" env:"SERVER_PORT" envDefault:"8080"`
    ReadTimeout  time.Duration `yaml:"readTimeout" env:"READ_TIMEOUT" envDefault:"30s"`
    WriteTimeout time.Duration `yaml:"writeTimeout" env:"WRITE_TIMEOUT" envDefault:"30s"`
}

type WebhookConfig struct {
    MaxPayloadSize    int64         `yaml:"maxPayloadSize" env:"MAX_PAYLOAD_SIZE" envDefault:"1048576"`
    DefaultTimeout    time.Duration `yaml:"defaultTimeout" env:"DEFAULT_TIMEOUT" envDefault:"30s"`
    QueueDepth        int           `yaml:"queueDepth" env:"QUEUE_DEPTH" envDefault:"10000"`
    RetryAttempts     int           `yaml:"retryAttempts" env:"RETRY_ATTEMPTS" envDefault:"3"`
}
```

### Step 3: Database Models (Day 2)
1. Define webhook entities
2. Create repository interfaces
3. Implement GORM models
4. Set up database connections

```go
// internal/model/webhook.go
package model

import (
    "time"
    "gorm.io/gorm"
)

type Webhook struct {
    ID          string            `gorm:"primaryKey;type:uuid" json:"id"`
    URL         string            `gorm:"not null;index" json:"url"`
    Method      string            `gorm:"not null" json:"method"`
    Payload     *JSON             `gorm:"type:jsonb" json:"payload"`
    Headers     *JSON             `gorm:"type:jsonb" json:"headers"`
    EndpointID  string            `gorm:"type:uuid;index" json:"endpointId"`
    Status      DeliveryStatus    `gorm:"not null;index" json:"status"`
    Attempts    int               `gorm:"not null;default:0" json:"attempts"`
    CreatedAt   time.Time         `gorm:"not null" json:"createdAt"`
    UpdatedAt   time.Time         `gorm:"not null" json:"updatedAt"`
    DeliveredAt *time.Time        `gorm:"index" json:"deliveredAt"`
    NextAttempt *time.Time        `gorm:"index" json:"nextAttempt"`
    LastError   string            `gorm:"type:text" json:"lastError"`
}

type DeliveryStatus string

const (
    StatusQueued    DeliveryStatus = "queued"
    StatusProcessing DeliveryStatus = "processing"
    StatusDelivered DeliveryStatus = "delivered"
    StatusFailed    DeliveryStatus = "failed"
    StatusRetrying  DeliveryStatus = "retrying"
    StatusDead      DeliveryStatus = "dead"
)

type WebhookEndpoint struct {
    ID             string    `gorm:"primaryKey;type:uuid" json:"id"`
    Name           string    `gorm:"not null" json:"name"`
    URL            string    `gorm:"not null;uniqueIndex" json:"url"`
    SecretKey      string    `gorm:"not null" json:"-"`
    IsActive       bool      `gorm:"not null;default:true" json:"isActive"`
    RateLimit      *int      `gorm:"type:integer" json:"rateLimit"`
    RetryPolicyID  *string   `gorm:"type:uuid" json:"retryPolicyId"`
    CreatedBy      string    `gorm:"not null" json:"createdBy"`
    CreatedAt      time.Time `gorm:"not null" json:"createdAt"`
    UpdatedAt      time.Time `gorm:"not null" json:"updatedAt"`
}
```

### Step 4: Repository Layer (Day 2-3)
1. Implement webhook repository interfaces
2. Create database operations
3. Add connection pooling
4. Implement caching layer

```go
// internal/repository/webhook.go
package repository

import (
    "context"
    "github.com/webhook-delivery/internal/model"
    "gorm.io/gorm"
)

type WebhookRepository interface {
    Create(ctx context.Context, webhook *model.Webhook) error
    GetByID(ctx context.Context, id string) (*model.Webhook, error)
    Update(ctx context.Context, webhook *model.Webhook) error
    ListByStatus(ctx context.Context, status model.DeliveryStatus, limit, offset int) ([]*model.Webhook, error)
    GetPendingForRetry(ctx context.Context, before time.Time) ([]*model.Webhook, error)
    DeleteDelivered(ctx context.Context, olderThan time.Time) error
}

type webhookRepository struct {
    db    *gorm.DB
    cache redis.Cmdable
}

func NewWebhookRepository(db *gorm.DB, cache redis.Cmdable) WebhookRepository {
    return &webhookRepository{
        db:    db,
        cache: cache,
    }
}

func (r *webhookRepository) Create(ctx context.Context, webhook *model.Webhook) error {
    if err := r.db.WithContext(ctx).Create(webhook).Error; err != nil {
        return pkg.WrapError(err, pkg.ErrCodeDatabase, "failed to create webhook")
    }
    
    // Invalidate cache
    r.cache.Del(ctx, fmt.Sprintf("webhook:%s", webhook.ID))
    
    return nil
}
```

### Step 5: Service Layer (Day 3-4)
1. Implement webhook service logic
2. Add validation
3. Create transaction handling
4. Implement idempotency

```go
// internal/service/webhook.go
package service

import (
    "context"
    "crypto/tls"
    "net/http"
    "time"
)

type WebhookService interface {
    SubmitWebhook(ctx context.Context, req *SubmitWebhookRequest) (*string, error)
    GetStatus(ctx context.Context, id string) (*WebhookStatus, error)
    RetryWebhook(ctx context.Context, id string) error
    CancelWebhook(ctx context.Context, id string) error
}

type webhookService struct {
    webhookRepo repository.WebhookRepository
    endpointRepo repository.EndpointRepository
    queue       queue.Producer
    logger      logger.Logger
    metrics     metrics.Metrics
}

func (s *webhookService) SubmitWebhook(ctx context.Context, req *SubmitWebhookRequest) (*string, error) {
    // Validate request
    if err := req.Validate(); err != nil {
        return nil, pkg.WrapError(err, pkg.ErrCodeValidation, "invalid request")
    }
    
    // Check endpoint exists and is active
    endpoint, err := s.endpointRepo.GetByURL(ctx, req.URL)
    if err != nil {
        return nil, pkg.WrapError(err, pkg.ErrCodeNotFound, "endpoint not found")
    }
    
    if !endpoint.IsActive {
        return nil, pkg.NewError(pkg.ErrCodeConflict, "endpoint is inactive")
    }
    
    // Apply rate limiting if configured
    if endpoint.RateLimit != nil {
        allowed, err := s.checkRateLimit(ctx, endpoint.ID, *endpoint.RateLimit)
        if err != nil {
            s.logger.Error("rate limit check failed", "error", err)
        } else if !allowed {
            return nil, pkg.NewError(pkg.ErrCodeTooManyRequests, "rate limit exceeded")
        }
    }
    
    // Create webhook record
    webhook := &model.Webhook{
        ID:         uuid.New().String(),
        URL:        req.URL,
        Method:     req.Method,
        Payload:    model.JSON(req.Payload),
        Headers:    model.JSON(req.Headers),
        EndpointID: endpoint.ID,
        Status:     model.StatusQueued,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    
    if err := s.webhookRepo.Create(ctx, webhook); err != nil {
        return nil, pkg.WrapError(err, pkg.ErrCodeDatabase, "failed to save webhook")
    }
    
    // Queue for processing
    if err := s.queue.Publish(ctx, queue.WebhookQueue, &queue.WebhookMessage{
        ID:       webhook.ID,
        Attempt:  0,
        Priority: req.Priority,
    }); err != nil {
        s.logger.Error("failed to queue webhook", "id", webhook.ID, "error", err)
        s.metrics.Increment("webhook.queue.errors")
    } else {
        s.metrics.Increment("webhook.submitted")
    }
    
    return &webhook.ID, nil
}
```

### Step 6: Queue Integration (Day 4-5)
1. Implement RabbitMQ producer
2. Create message schemas
3. Add error handling
4. Implement acknowledgment patterns

```go
// internal/queue/producer.go
package queue

import (
    "github.com/streadway/amqp"
)

type Producer interface {
    Publish(ctx context.Context, queue string, message interface{}) error
    Close() error
}

type rabbitProducer struct {
    conn    *amqp.Connection
    channel *amqp.Channel
}

func NewRabbitProducer(url string) (Producer, error) {
    conn, err := amqp.Dial(url)
    if err != nil {
        return nil, err
    }
    
    ch, err := conn.Channel()
    if err != nil {
        return nil, err
    }
    
    // Declare queues
    for _, q := range []string{WebhookQueue, RetryQueue, DeadLetterQueue} {
        _, err = ch.QueueDeclare(
            q,
            true,  // durable
            false, // autoDelete
            false, // exclusive
            false, // noWait
            amqp.Table{
                "x-dead-letter-exchange":    "webhook-dlx",
                "x-message-ttl":             3600000, // 1 hour
                "x-max-length":              100000,  // 100k messages
                "x-overflow":                "reject-publish",
            },
        )
        if err != nil {
            return nil, err
        }
    }
    
    return &rabbitProducer{
        conn:    conn,
        channel: ch,
    }, nil
}

func (p *rabbitProducer) Publish(ctx context.Context, queueName string, message interface{}) error {
    body, err := json.Marshal(message)
    if err != nil {
        return err
    }
    
    return p.channel.Publish(
        "",        // exchange
        queueName, // routing key
        false,     // mandatory
        false,     // immediate
        amqp.Publishing{
            ContentType: "application/json",
            Body:        body,
            Timestamp:   time.Now(),
            MessageId:   uuid.New().String(),
        },
    )
}
```

### Step 7: HTTP Handlers (Day 5-6)
1. Implement REST API endpoints
2. Add request validation
3. Create middleware for logging
4. Implement error responses

```go
// internal/handler/webhook.go
package handler

import (
    "net/http"
    
    "github.com/gin-gonic/gin"
)

type WebhookHandler struct {
    service service.WebhookService
    logger  logger.Logger
}

func NewWebhookHandler(service service.WebhookService, logger logger.Logger) *WebhookHandler {
    return &WebhookHandler{
        service: service,
        logger:  logger,
    }
}

type SubmitWebhookRequest struct {
    URL      string            `json:"url" binding:"required,url"`
    Method   string            `json:"method" binding:"required,oneof=POST PUT PATCH"`
    Payload  json.RawMessage   `json:"payload"`
    Headers  map[string]string `json:"headers"`
    Priority int               `json:"priority" binding:"min=0,max=10"`
}

func (r *SubmitWebhookRequest) Validate() error {
    if len(r.Payload) > 1048576 {
        return errors.New("payload too large")
    }
    return nil
}

func (h *WebhookHandler) SubmitWebhook(c *gin.Context) {
    var req SubmitWebhookRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "invalid request: " + err.Error(),
        })
        return
    }
    
    id, err := h.service.SubmitWebhook(c.Request.Context(), &req)
    if err != nil {
        h.handleError(c, err)
        return
    }
    
    c.JSON(http.StatusAccepted, gin.H{
        "id": id,
        "message": "webhook submitted for delivery",
    })
}

func (h *WebhookHandler) GetStatus(c *gin.Context) {
    id := c.Param("id")
    if id == "" {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "webhook ID is required",
        })
        return
    }
    
    status, err := h.service.GetStatus(c.Request.Context(), id)
    if err != nil {
        h.handleError(c, err)
        return
    }
    
    c.JSON(http.StatusOK, status)
}

func (h *WebhookHandler) handleError(c *gin.Context, err error) {
    switch {
    case errors.Is(err, pkg.ErrCodeValidation):
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
    case errors.Is(err, pkg.ErrCodeNotFound):
        c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
    case errors.Is(err, pkg.ErrCodeTooManyRequests):
        c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
    default:
        h.logger.Error("internal server error", "error", err)
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "internal server error",
        })
    }
}
```

### Step 8: Main Application (Day 6)
1. Wire up all dependencies
2. Configure HTTP server
3. Add graceful shutdown
4. Implement health checks

```go
// cmd/service/main.go
package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "github.com/webhook-delivery/internal/config"
    "github.com/webhook-delivery/internal/handler"
    "github.com/webhook-delivery/internal/repository"
    "github.com/webhook-delivery/internal/service"
    "github.com/webhook-delivery/pkg/logger"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        logger.Fatal("failed to load config", "error", err)
    }
    
    // Initialize dependencies
    db, err := database.NewConnection(cfg.Database)
    if err != nil {
        logger.Fatal("failed to connect to database", "error", err)
    }
    
    redis, err := redis.NewConnection(cfg.Redis)
    if err != nil {
        logger.Fatal("failed to connect to redis", "error", err)
    }
    
    queue, err := queue.NewProducer(cfg.RabbitMQ.URL)
    if err != nil {
        logger.Fatal("failed to connect to queue", "error", err)
    }
    
    // Wire up repositories
    webhookRepo := repository.NewWebhookRepository(db, redis)
    endpointRepo := repository.NewEndpointRepository(db, redis)
    
    // Wire up services
    webhookService := service.NewWebhookService(webhookRepo, endpointRepo, queue)
    
    // Wire up handlers
    webhookHandler := handler.NewWebhookHandler(webhookService)
    
    // Setup router
    router := gin.New()
    router.Use(gin.Logger())
    router.Use(gin.Recovery())
    router.Use(middleware.RequestID())
    router.Use(middleware.Metrics())
    
    // Register routes
    api := router.Group("/api/v1")
    {
        api.POST("/webhooks", webhookHandler.SubmitWebhook)
        api.GET("/webhooks/:id/status", webhookHandler.GetStatus)
        api.POST("/webhooks/:id/retry", webhookHandler.RetryWebhook)
        api.DELETE("/webhooks/:id", webhookHandler.CancelWebhook)
    }
    
    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "healthy"})
    })
    
    // Start server
    srv := &http.Server{
        Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
        Handler:      router,
        ReadTimeout:  cfg.Server.ReadTimeout,
        WriteTimeout: cfg.Server.WriteTimeout,
    }
    
    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatal("server failed", "error", err)
        }
    }()
    
    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := srv.Shutdown(ctx); err != nil {
        logger.Error("server shutdown failed", "error", err)
    }
    
    logger.Info("server stopped")
}
```

### Step 9: Unit Tests (Day 7)
1. Write tests for each component
2. Mock external dependencies
3. Achieve 90%+ code coverage
4. Test edge cases

```go
// tests/service/webhook_test.go
package service_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

type MockWebhookRepository struct {
    mock.Mock
}

func (m *MockWebhookRepository) Create(ctx context.Context, webhook *model.Webhook) error {
    args := m.Called(ctx, webhook)
    return args.Error(0)
}

func TestWebhookService_SubmitWebhook_Success(t *testing.T) {
    // Arrange
    mockRepo := new(MockWebhookRepository)
    mockEndpointRepo := new(MockEndpointRepository)
    mockQueue := new(MockProducer)
    
    service := service.NewWebhookService(mockRepo, mockEndpointRepo, mockQueue)
    
    req := &service.SubmitWebhookRequest{
        URL:    "https://example.com/webhook",
        Method: "POST",
        Payload: json.RawMessage(`{"test": "data"}`),
    }
    
    endpoint := &model.WebhookEndpoint{
        ID:       "endpoint-123",
        URL:      req.URL,
        IsActive: true,
    }
    
    mockEndpointRepo.On("GetByURL", mock.Anything, req.URL).Return(endpoint, nil)
    mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Webhook")).Return(nil)
    mockQueue.On("Publish", mock.Anything, queue.WebhookQueue, mock.Anything).Return(nil)
    
    // Act
    id, err := service.SubmitWebhook(context.Background(), req)
    
    // Assert
    assert.NoError(t, err)
    assert.NotNil(t, id)
    mockRepo.AssertExpectations(t)
    mockQueue.AssertExpectations(t)
}
```

### Step 10: Integration Tests (Day 8)
1. Set up test database
2. Test API endpoints
3. Validate queue integration
4. Test error scenarios

```go
// tests/integration/api_test.go
package integration

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    
    "github.com/stretchr/testify/assert"
)

func TestSubmitWebhook_Integration(t *testing.T) {
    // Setup test environment
    testDB := setupTestDB(t)
    defer cleanupTestDB(t, testDB)
    
    // Setup test server
    router := setupTestRouter(testDB)
    
    // Prepare request
    payload := map[string]interface{}{
        "url":     "https://example.com/webhook",
        "method":  "POST",
        "payload": map[string]string{"event": "user.created"},
    }
    
    body, _ := json.Marshal(payload)
    req := httptest.NewRequest("POST", "/api/v1/webhooks", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    
    // Execute
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    // Assert
    assert.Equal(t, http.StatusAccepted, w.Code)
    
    var response map[string]interface{}
    err := json.Unmarshal(w.Body.Bytes(), &response)
    assert.NoError(t, err)
    assert.Contains(t, response, "id")
    
    // Verify webhook was created in database
    id := response["id"].(string)
    var webhook model.Webhook
    err = testDB.First(&webhook, "id = ?", id).Error
    assert.NoError(t, err)
    assert.Equal(t, model.StatusQueued, webhook.Status)
}
```

## Acceptance Criteria

### Must-Have
- [ ] HTTP API accepts webhook submissions
- [ ] Webhooks are stored in database
- [ ] Messages are published to queue
- [ ] All endpoints have proper error handling
- [ ] Service includes health checks
- [ ] Request/response formats documented

### Should-Have
- [ ] Request validation with proper error messages
- [ ] Rate limiting per endpoint
- [ ] Metrics exported for Prometheus
- [ ] Structured logging with correlation IDs
- [ ] Configuration validation at startup

### Could-Have
- [ ] Circuit breaker for external calls
- [ ] Request compression
- [ ] API versioning
- [ ] OpenAPI documentation generation

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| API request processing | < 50ms | p95 |
| Database query time | < 10ms | p90 |
| Queue publish latency | < 5ms | p95 |
| Memory usage | < 256MB | steady state |
| CPU usage | < 70% | average |

## Testing Requirements

1. **Unit Tests**
   - 90%+ code coverage
   - Mock all external dependencies
   - Test all error paths

2. **Integration Tests**
   - Real database connections
   - Queue integration validation
   - End-to-end API tests

3. **Performance Tests**
   - Load testing with k6
   - Memory leak detection
   - Concurrent request handling

## Deliverables

1. **Source Code**
   - Complete service implementation
   - Unit and integration tests
   - Docker configuration
   - Deployment manifests

2. **Documentation**
   - API specification (OpenAPI)
   - Architecture diagrams
   - README with setup instructions

3. **Test Results**
   - Coverage reports
   - Performance benchmarks
   - Security scan results

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Database contention | Use connection pooling, implement caching |
| Queue bottleneck | Monitor queue depth, implement backpressure |
| Memory leaks | Regular profiling, memory limits |
| API breaking changes | Version from v1, deprecation policy |

---

## Checklists

### Code Review Checklist
- [ ] Unit tests passing
- [ ] Error handling complete
- [ ] Logging appropriate
- [ ] Security considerations addressed
- [ ] Performance optimized

### Pre-Deployment Checklist
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Configuration validated
- [ ] Security scans passed

---

*Reviewer: Senior Backend Engineer*  
* Approved by: Tech Lead, Security Team*  
* Completion Date: Expected 2025-02-25*