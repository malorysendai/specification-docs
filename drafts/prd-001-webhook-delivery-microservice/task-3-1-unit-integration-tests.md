# Task 3.1: Unit & Integration Tests

**Task ID:** T3-001  
**Phase:** Phase 3 - Testing & Deployment  
**Duration:** 7 days  
**Assignee:** QA Engineer  
**Priority:** Critical  

## Overview

This task focuses on implementing comprehensive unit and integration tests for the Webhook Delivery Microservice. The goal is to achieve 90%+ code coverage for unit tests, validate component interactions through integration tests, and ensure the service behaves correctly under various scenarios. Test automation will be implemented in the CI/CD pipeline to catch regressions early.

## Prerequisites

- Core service implementation complete (Tasks 2.1-2.3)
- Test database environment provisioned
- Mock services configured
- Test data fixtures prepared
- Testing framework selected

## Detailed Steps

### Step 1: Set Up Testing Infrastructure (Day 1)
1. Configure test database schema
2. Set up test message queue
3. Create test Redis instance
4. Initialize test data fixtures
5. Configure test environment variables

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  postgres-test:
    image: postgres:15
    environment:
      POSTGRES_DB: webhook_test
      POSTGRES_USER: test
      POSTGRES_PASSWORD: testpass
    ports:
      - "5433:5432"
    volumes:
      - ./scripts/test-db-init.sql:/docker-entrypoint-initdb.d/init.sql

  redis-test:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    command: redis-server --appendonly yes

  rabbitmq-test:
    image: rabbitmq:3-management
    environment:
      RABBITMQ_DEFAULT_USER: test
      RABBITMQ_DEFAULT_PASS: testpass
    ports:
      - "5673:5672"
      - "15673:15672"
```

```go
// tests/setup_test.go
package tests

import (
    "database/sql"
    "fmt"
    "os"
    "testing"
    "time"
    
    "github.com/ory/dockertest/v3"
    "github.com/ory/dockertest/v3/docker"
    _ "github.com/lib/pq"
    _ "github.com/streadway/amqp"
    "github.com/go-redis/redis/v8"
)

var (
    testDB       *sql.DB
    testRedis    *redis.Client
    testQueue    queue.Producer
    testConsumer queue.Consumer
)

func TestMain(m *testing.M) {
    // Load test configuration
    loadTestConfig()
    
    // Setup test containers
    if err := setupTestContainers(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to setup test containers: %v\n", err)
        os.Exit(1)
    }
    
    // Run migrations
    runMigrations()
    
    // Run tests
    code := m.Run()
    
    // Cleanup
    cleanup()
    
    os.Exit(code)
}

func setupTestContainers() error {
    pool, err := dockertest.NewPool("")
    if err != nil {
        return err
    }
    
    // PostgreSQL
    pgResource, err := pool.RunWithOptions(&dockertest.RunOptions{
        Repository: "postgres",
        Tag:        "15",
        Env: []string{
            "POSTGRES_DB=webhook_test",
            "POSTGRES_USER=test",
            "POSTGRES_PASSWORD=testpass",
        },
    })
    if err != nil {
        return err
    }
    
    // Wait for PostgreSQL to be ready
    if err := pool.Retry(func() error {
        var err error
        testDB, err = sql.Open("postgres", fmt.Sprintf(
            "host=localhost port=%s user=test password=testpass dbname=webhook_test sslmode=disable",
            pgResource.GetPort("5432/tcp"),
        ))
        if err != nil {
            return err
        }
        return testDB.Ping()
    }); err != nil {
        return err
    }
    
    // Redis
    redisResource, err := pool.RunWithOptions(&dockertest.RunOptions{
        Repository: "redis",
        Tag:        "7-alpine",
    })
    if err != nil {
        return err
    }
    
    if err := pool.Retry(func() error {
        testRedis = redis.NewClient(&redis.Options{
            Addr: fmt.Sprintf("localhost:%s", redisResource.GetPort("6379/tcp")),
        })
        return testRedis.Ping(context.Background()).Err()
    }); err != nil {
        return err
    }
    
    return nil
}
```

### Step 2: Unit Tests Implementation (Days 2-4)
1. Write tests for service layer
2. Test repository layer with real database
3. Test HTTP handlers and middleware
4. Test retry mechanisms
5. Test authentication/authorization

```go
// tests/service/webhook_test.go
package service_test

import (
    "context"
    "bytes"
    "encoding/json"
    "errors"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
    "go.uber.org/zap/zaptest"
    
    "github.com/webhook-delivery/internal/model"
    "github.com/webhook-delivery/internal/service"
    "github.com/webhook-delivery/internal/repository/mocks"
    "github.com/webhook-delivery/internal/queue/mocks"
)

type WebhookServiceSuite struct {
    webhookRepo    *mocks.WebhookRepository
    endpointRepo   *mocks.EndpointRepository
    queue          *mocks.Producer
    signatureSvc   *mocks.SignatureService
    rateLimiter    *mocks.RateLimiter
    logger         *zaptest.Logger
    service        *service.WebhookService
}

func (suite *WebhookServiceSuite) SetupTest() {
    suite.webhookRepo = &mocks.WebhookRepository{}
    suite.endpointRepo = &mocks.EndpointRepository{}
    suite.queue = &mocks.Producer{}
    suite.signatureSvc = &mocks.SignatureService{}
    suite.rateLimiter = &mocks.RateLimiter{}
    suite.logger = zaptest.NewLogger(t)
    
    suite.service = service.NewWebhookService(
        suite.webhookRepo,
        suite.endpointRepo,
        suite.queue,
        suite.signatureSvc,
        suite.rateLimiter,
        suite.logger,
    )
}

func TestWebhookService_SubmitWebhook_Success(t *testing.T) {
    // Setup
    suite := &WebhookServiceSuite{}
    suite.SetupTest()
    
    req := &service.SubmitWebhookRequest{
        URL:    "https://example.com/webhook",
        Method: "POST",
        Payload: json.RawMessage(`{"event": "user.created"}`),
        Headers: map[string]string{"Content-Type": "application/json"},
    }
    
    endpoint := &model.WebhookEndpoint{
        ID:       "endpoint-123",
        URL:      req.URL,
        IsActive: true,
        SecretKey: "test-secret",
    }
    
    expectedWebhook := &model.Webhook{
        ID:         "webhook-456",
        URL:        req.URL,
        Method:     req.Method,
        Payload:    model.JSON(req.Payload),
        Headers:    model.JSON(req.Headers),
        EndpointID: endpoint.ID,
        Status:     model.StatusQueued,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    
    // Mock expectations
    suite.endpointRepo.On("GetByURL", mock.Anything, req.URL).Return(endpoint, nil)
    suite.rateLimiter.On("Check", mock.Anything, endpoint.ID, mock.Anything).Return(true, nil)
    suite.webhookRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Webhook")).Return(nil)
    suite.queue.On("Publish", mock.Anything, queue.WebhookQueue, mock.Anything).Return(nil)
    
    // Execute
    webhookID, err := suite.service.SubmitWebhook(context.Background(), req)
    
    // Assert
    require.NoError(t, err)
    assert.NotNil(t, webhookID)
    
    suite.endpointRepo.AssertExpectations(t)
    suite.webhookRepo.AssertExpectations(t)
    suite.queue.AssertExpectations(t)
}

func TestWebhookService_SubmitWebhook_EndpointNotFound(t *testing.T) {
    // Setup
    suite := &WebhookServiceSuite{}
    suite.SetupTest()
    
    req := &service.SubmitWebhookRequest{
        URL:    "https://example.com/webhook",
        Method: "POST",
    }
    
    // Mock expectations
    suite.endpointRepo.On("GetByURL", mock.Anything, req.URL).
        Return(nil, errors.New("endpoint not found"))
    
    // Execute
    webhookID, err := suite.service.SubmitWebhook(context.Background(), req)
    
    // Assert
    require.Error(t, err)
    assert.Nil(t, webhookID)
    assert.Contains(t, err.Error(), "endpoint not found")
    
    suite.endpointRepo.AssertExpectations(t)
}

func TestWebhookService_SubmitWebhook_RateLimitExceeded(t *testing.T) {
    // Setup
    suite := &WebhookServiceSuite{}
    suite.SetupTest()
    
    req := &service.SubmitWebhookRequest{
        URL:    "https://example.com/webhook",
        Method: "POST",
    }
    
    endpoint := &model.WebhookEndpoint{
        ID:         "endpoint-123",
        URL:        req.URL,
        IsActive:   true,
        RateLimit:  &[]int{100}[0],
    }
    
    // Mock expectations
    suite.endpointRepo.On("GetByURL", mock.Anything, req.URL).Return(endpoint, nil)
    suite.rateLimiter.On("Check", mock.Anything, endpoint.ID, *endpoint.RateLimit).
        Return(false, nil)
    
    // Execute
    webhookID, err := suite.service.SubmitWebhook(context.Background(), req)
    
    // Assert
    require.Error(t, err)
    assert.Nil(t, webhookID)
    
    var appErr *pkg.AppError
    assert.ErrorAs(t, err, &appErr)
    assert.Equal(t, pkg.ErrCodeTooManyRequests, appErr.Code)
    
    suite.endpointRepo.AssertExpectations(t)
    suite.rateLimiter.AssertExpectations(t)
}

func TestWebhookService_SubmitWebhook_ValidationErrors(t *testing.T) {
    testCases := []struct {
        name        string
        request     *service.SubmitWebhookRequest
        expectedErr string
    }{
        {
            name: "Empty URL",
            request: &service.SubmitWebhookRequest{
                URL:    "",
                Method: "POST",
            },
            expectedErr: "url is required",
        },
        {
            name: "Invalid URL",
            request: &service.SubmitWebhookRequest{
                URL:    "not-a-valid-url",
                Method: "POST",
            },
            expectedErr: "invalid URL format",
        },
        {
            name: "Unsupported Method",
            request: &service.SubmitWebhookRequest{
                URL:    "https://example.com/webhook",
                Method: "DELETE",
            },
            expectedErr: "method must be one of",
        },
        {
            name: "Payload too large",
            request: &service.SubmitWebhookRequest{
                URL:     "https://example.com/webhook",
                Method:  "POST",
                Payload: bytes.Repeat([]byte("x"), 2*1024*1024), // 2MB
            },
            expectedErr: "payload too large",
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            suite := &WebhookServiceSuite{}
            suite.SetupTest()
            
            // Execute
            webhookID, err := suite.service.SubmitWebhook(context.Background(), tc.request)
            
            // Assert
            require.Error(t, err)
            assert.Nil(t, webhookID)
            assert.Contains(t, err.Error(), tc.expectedErr)
        })
    }
}
```

```go
// tests/repo/webhook_repository_test.go
package repository_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    
    "github.com/webhook-delivery/internal/model"
    "github.com/webhook-delivery/internal/repository"
)

type WebhookRepositorySuite struct {
    suite.Suite
    db         *gorm.DB
    repository repository.WebhookRepository
    ctx        context.Context
}

func (suite *WebhookRepositorySuite) SetupSuite() {
    suite.ctx = context.Background()
    
    // Connect to test database
    db, err := gorm.Open(postgres.Open(
        "host=localhost port=5433 user=test password=testpass dbname=webhook_test sslmode=disable",
    ), &gorm.Config{})
    require.NoError(suite.T(), err)
    
    suite.db = db
    suite.repository = repository.NewWebhookRepository(db)
    
    // Auto migrate
    err = db.AutoMigrate(&model.Webhook{}, &model.WebhookEndpoint{})
    require.NoError(suite.T(), err)
}

func (suite *WebhookRepositorySuite) SetupTest() {
    // Clean database
    suite.db.Exec("TRUNCATE TABLE webhooks, webhook_endpoints CASCADE")
}

func (suite *WebhookRepositorySuite) TestCreate() {
    webhook := &model.Webhook{
        ID:         "test-id",
        URL:        "https://example.com/webhook",
        Method:     "POST",
        Payload:    model.NewJSON(map[string]string{"test": "data"}),
        EndpointID: "endpoint-123",
        Status:     model.StatusQueued,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    
    // Create webhook
    err := suite.repository.Create(suite.ctx, webhook)
    require.NoError(suite.T(), err)
    
    // Verify it was created
    var found model.Webhook
    err = suite.db.First(&found, "id = ?", webhook.ID).Error
    require.NoError(suite.T(), err)
    
    assert.Equal(suite.T(), webhook.ID, found.ID)
    assert.Equal(suite.T(), webhook.URL, found.URL)
    assert.Equal(suite.T(), webhook.Status, found.Status)
}

func (suite *WebhookRepositorySuite) TestGetByID() {
    // Create test webhook
    webhook := &model.Webhook{
        ID:         "test-id",
        URL:        "https://example.com/webhook",
        Method:     "POST",
        Status:     model.StatusQueued,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    err := suite.db.Create(webhook).Error
    require.NoError(suite.T(), err)
    
    // Get by ID
    found, err := suite.repository.GetByID(suite.ctx, webhook.ID)
    require.NoError(suite.T(), err)
    require.NotNil(suite.T(), found)
    
    assert.Equal(suite.T(), webhook.ID, found.ID)
    assert.Equal(suite.T(), webhook.URL, found.URL)
}

func (suite *WebhookRepositorySuite) TestUpdate() {
    // Create test webhook
    webhook := &model.Webhook{
        ID:         "test-id",
        URL:        "https://example.com/webhook",
        Method:     "POST",
        Status:     model.StatusQueued,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    err := suite.db.Create(webhook).Error
    require.NoError(suite.T(), err)
    
    // Update status
    webhook.Status = model.StatusDelivered
    webhook.DeliveredAt = &time.Time{}
    *webhook.DeliveredAt = time.Now()
    
    err = suite.repository.Update(suite.ctx, webhook)
    require.NoError(suite.T(), err)
    
    // Verify update
    var found model.Webhook
    err = suite.db.First(&found, "id = ?", webhook.ID).Error
    require.NoError(suite.T(), err)
    
    assert.Equal(suite.T(), model.StatusDelivered, found.Status)
    assert.NotNil(suite.T(), found.DeliveredAt)
}

func (suite *WebhookRepositorySuite) TestListByStatus() {
    // Create test webhooks
    webhooks := []*model.Webhook{
        {
            ID:     "webhook-1",
            Status: model.StatusQueued,
        },
        {
            ID:     "webhook-2",
            Status: model.StatusQueued,
        },
        {
            ID:     "webhook-3",
            Status: model.StatusDelivered,
        },
    }
    
    for _, w := range webhooks {
        err := suite.db.Create(w).Error
        require.NoError(suite.T(), err)
    }
    
    // List queued webhooks
    results, err := suite.repository.ListByStatus(suite.ctx, model.StatusQueued, 10, 0)
    require.NoError(suite.T(), err)
    
    assert.Len(suite.T(), results, 2)
    assert.Equal(suite.T(), "webhook-1", results[0].ID)
    assert.Equal(suite.T(), "webhook-2", results[1].ID)
}

func (suite *WebhookRepositorySuite) TestGetPendingForRetry() {
    now := time.Now()
    
    // Create test webhooks
    webhooks := []*model.Webhook{
        {
            ID:          "webhook-1",
            Status:      model.StatusRetrying,
            NextAttempt: &now,
        },
        {
            ID:          "webhook-2",
            Status:      model.StatusRetrying,
            NextAttempt: &[]time.Time{now.Add(1 * time.Hour)}[0],
        },
        {
            ID:          "webhook-3",
            Status:      model.StatusDelivered,
            NextAttempt: nil,
        },
    }
    
    for _, w := range webhooks {
        err := suite.db.Create(w).Error
        require.NoError(suite.T(), err)
    }
    
    // Get webhooks ready for retry
    results, err := suite.repository.GetPendingForRetry(suite.ctx, now.Add(30*time.Second))
    require.NoError(suite.T(), err)
    
    assert.Len(suite.T(), results, 1)
    assert.Equal(suite.T(), "webhook-1", results[0].ID)
}

func TestWebhookRepositorySuite(t *testing.T) {
    suite.Run(t, new(WebhookRepositorySuite))
}
```

### Step 3: Integration Tests (Days 5-6)
1. Test complete webhook delivery flow
2. Test retry mechanism end-to-end
3. Test authentication flows
4. Test queue integration
5. API integration tests

```go
// tests/integration/webhook_delivery_test.go
package integration

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "http"
    "net/http/httptest"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/webhook-delivery/internal/model"
    "github.com/webhook-delivery/internal/server"
)

func TestWebhookDelivery_Integration(t *testing.T) {
    // Setup test server
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Verify webhook delivery
        assert.Equal(t, "POST", r.Method)
        assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
        assert.NotEmpty(t, r.Header.Get("X-Webhook-Signature"))
        assert.NotEmpty(t, r.Header.Get("X-Webhook-Timestamp"))
        
        var payload map[string]interface{}
        err := json.NewDecoder(r.Body).Decode(&payload)
        require.NoError(t, err)
        assert.Equal(t, "user.created", payload["event"])
        
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()
    
    // Create test endpoint
    endpoint := &model.WebhookEndpoint{
        ID:         "endpoint-test",
        Name:       "Test Endpoint",
        URL:        ts.URL,
        SecretKey:  "test-secret",
        Algorithm:  "sha256",
        IsActive:   true,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    err := testDB.Create(endpoint).Error
    require.NoError(t, err)
    
    // Submit webhook
    payload := map[string]interface{}{
        "event": "user.created",
        "data":  map[string]string{"userId": "123"},
    }
    
    body, _ := json.Marshal(payload)
    req := httptest.NewRequest("POST", "/api/v1/webhooks", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer valid-token")
    
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, http.StatusAccepted, w.Code)
    
    var response map[string]interface{}
    err = json.Unmarshal(w.Body.Bytes(), &response)
    require.NoError(t, err)
    
    webhookID, ok := response["id"].(string)
    require.True(t, ok)
    assert.NotEmpty(t, webhookID)
    
    // Wait for delivery
    time.Sleep(5 * time.Second)
    
    // Check status
    req = httptest.NewRequest("GET", fmt.Sprintf("/api/v1/webhooks/%s/status", webhookID), nil)
    req.Header.Set("Authorization", "Bearer valid-token")
    
    w = httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, http.StatusOK, w.Code)
    
    var status map[string]interface{}
    err = json.Unmarshal(w.Body.Bytes(), &status)
    require.NoError(t, err)
    
    assert.Equal(t, "delivered", status["status"])
    assert.NotNil(t, status["deliveredAt"])
}

func TestWebhookDelivery_RetryFlow(t *testing.T) {
    attemptCount := 0
    
    // Setup test server that fails initially
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        attemptCount++
        if attemptCount < 3 {
            w.WriteHeader(http.StatusServiceUnavailable)
            return
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()
    
    // Create test endpoint with aggressive retry policy
    endpoint := &model.WebhookEndpoint{
        ID:          "endpoint-retry",
        Name:        "Retry Endpoint",
        URL:         ts.URL,
        SecretKey:   "test-secret",
        Algorithm:   "sha256",
        IsActive:    true,
        RetryPolicy: "policy-aggressive",
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
    err := testDB.Create(endpoint).Error
    require.NoError(t, err)
    
    // Submit webhook
    payload := map[string]interface{}{"event": "retry.test"}
    body, _ := json.Marshal(payload)
    
    req := httptest.NewRequest("POST", "/api/v1/webhooks", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer valid-token")
    
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, http.StatusAccepted, w.Code)
    
    var response map[string]interface{}
    err = json.Unmarshal(w.Body.Bytes(), &response)
    require.NoError(t, err)
    
    webhookID := response["id"].(string)
    
    // Wait for retries
    time.Sleep(10 * time.Second)
    
    // Check final status
    req = httptest.NewRequest("GET", fmt.Sprintf("/api/v1/webhooks/%s/status", webhookID), nil)
    req.Header.Set("Authorization", "Bearer valid-token")
    
    w = httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, http.StatusOK, w.Code)
    
    var status map[string]interface{}
    err = json.Unmarshal(w.Body.Bytes(), &status)
    require.NoError(t, err)
    
    assert.Equal(t, "delivered", status["status"])
    assert.Equal(t, float64(3), status["attempts"])
    assert.NotNil(t, status["deliveredAt"])
}

func TestAuthentication_Integration(t *testing.T) {
    testCases := []struct {
        name           string
        authHeader     string
        expectedStatus int
    }{
        {
            name:           "Valid JWT",
            authHeader:     "Bearer valid-jwt-token",
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Invalid JWT",
            authHeader:     "Bearer invalid-token",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "No Authorization",
            authHeader:     "",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Wrong Scheme",
            authHeader:     "Basic token",
            expectedStatus: http.StatusUnauthorized,
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            req := httptest.NewRequest("GET", "/api/v1/webhooks", nil)
            if tc.authHeader != "" {
                req.Header.Set("Authorization", tc.authHeader)
            }
            
            w := httptest.NewRecorder()
            router.ServeHTTP(w, req)
            
            assert.Equal(t, tc.expectedStatus, w.Code)
        })
    }
}

func TestRateLimiting_Integration(t *testing.T) {
    // Create endpoint with rate limit
    endpoint := &model.WebhookEndpoint{
        ID:        "endpoint-ratelimit",
        Name:      "Rate Limit Endpoint",
        URL:       "https://example.com/webhook",
        RateLimit: &[]int{2}[0], // 2 requests per minute
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
    err := testDB.Create(endpoint).Error
    require.NoError(t, err)
    
    // Send requests exceeding rate limit
    payload := map[string]interface{}{"event": "rate.test"}
    
    for i := 0; i < 5; i++ {
        body, _ := json.Marshal(payload)
        req := httptest.NewRequest("POST", "/api/v1/webhooks", bytes.NewBuffer(body))
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", "Bearer valid-token")
        
        w := httptest.NewRecorder()
        router.ServeHTTP(w, req)
        
        if i < 2 {
            assert.Equal(t, http.StatusAccepted, w.Code)
        } else {
            assert.Equal(t, http.StatusTooManyRequests, w.Code)
        }
    }
}
```

### Step 4: Test Automation (Day 7)
1. Configure CI/CD pipeline for tests
2. Set up test reporting
3. Add coverage reporting
4. Configure test notifications

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_USER: test
          POSTGRES_DB: webhook_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
      
      rabbitmq:
        image: rabbitmq:3-management
        env:
          RABBITMQ_DEFAULT_USER: test
          RABBITMQ_DEFAULT_PASS: test
        options: >-
          --health-cmd "rabbitmq-diagnostics -q ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5672:5672
          - 15672:15672
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-
    
    - name: Install dependencies
      run: |
        go mod download
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
        go install github.com/securecodewarrior/github-actions-add-issue-reaction@latest
    
    - name: Run linter
      run: golangci-lint run -v
    
    - name: Run unit tests
      env:
        DATABASE_URL: postgres://test:test@localhost:5432/webhook_test?sslmode=disable
        REDIS_URL: redis://localhost:6379
        RABBITMQ_URL: amqp://test:test@localhost:5672/
      run: |
        go test -v -race -coverprofile=coverage.out ./... 2>&1 | tee test.log
        
    - name: Verify test coverage
      run: |
        go tool cover -func=coverage.out | grep total | awk '{print $3}' | grep -E '\d+\.\d+' >/dev/null
        TOTAL_COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
        echo "Total coverage: ${TOTAL_COVERAGE}%"
        if (( $(echo "$TOTAL_COVERAGE < 90" | bc -l) )); then
          echo "Coverage below 90%"
          exit 1
        fi
    
    - name: Generate coverage report
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const coverage = fs.readFileSync('coverage.out', 'utf8');
          // Parse and format coverage for PR comment
          
    - name: Run integration tests
      env:
        DATABASE_URL: postgres://test:test@localhost:5432/webhook_test?sslmode=disable
        REDIS_URL: redis://localhost:6379
        RABBITMQ_URL: amqp://test:test@localhost:5672/
      run: |
        go test -v -tags=integration ./tests/integration/...
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
        flags: unittests
        name: codecov-umbrella
    
    - name: Add coverage comment
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const testLog = fs.readFileSync('test.log', 'utf8');
          
          // Extract test results
          const totalTests = (testLog.match(/=== RUN/g) || []).length;
          const passedTests = (testLog.match(/--- PASS:/g) || []).length;
          const failedTests = (testLog.match(/--- FAIL:/g) || []).length;
          
          const comment = `## Test Results
          
          | Metric | Value |
          |--------|-------|
          | Total Tests | ${totalTests} |
          | Passed | ${passedTests} |
          | Failed | ${failedTests} |
          | Coverage | ${process.env.TOTAL_COVERAGE}% |
          
          <details>
          <summary>Test Log</summary>
          
          \`\`\`
          ${testLog}
          \`\`\`
          </details>`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

## Acceptance Criteria

### Must-Have
- [ ] Unit test coverage ≥ 90%
- [ ] All critical paths tested
- [ ] Integration tests cover main workflows
- [ ] Tests run in CI/CD pipeline
- [ ] No flaky tests
- [ ] Mock external dependencies properly

### Should-Have
- [ ] Property-based testing for edge cases
- [ ] Performance tests
- [ ] Load testing scenarios
- [ ] Chaos engineering tests
- [ ] Contract tests with consumers

### Could-Have
- [ ] Mutation tests
- [ ] Fuzz testing
- [ ] Visual regression tests
- [ ] A/B test frameworks

## Testing Framework

### Unit Testing
- **Framework**: testify
- **Mocking**: testify/mock
- **Assertions**: testify/assert
- **Coverage**: go tool cover

### Integration Testing
- **Fixtures**: testify/suite
- **Containers**: dockertest
- **Database**: test database
- **Cleanup**: automatic cleanup

### Test Categories
```
tests/
├── unit/
│   ├── service/
│   ├── repository/
│   ├── handler/
│   └── middleware/
├── integration/
│   ├── api/
│   ├── delivery/
│   └── auth/
├── e2e/
│   └── scenarios/
├── performance/
│   └── benchmarks/
└── fixtures/
    ├── data/
    └── configs/
```

## Test Data Management

1. **Factory Pattern for Test Data**
```go
// tests/factories/webhook_factory.go
package factories

type WebhookFactory struct {
    ID         string
    URL        string
    Method     string
    Payload    interface{}
    Status     model.DeliveryStatus
}

func NewWebhookFactory() *WebhookFactory {
    return &WebhookFactory{
        ID:      uuid.New().String(),
        URL:     "https://example.com/webhook",
        Method:  "POST",
        Payload: map[string]string{"test": "data"},
        Status:  model.StatusQueued,
    }
}

func (f *WebhookFactory) Build() *model.Webhook {
    return &model.Webhook{
        ID:        f.ID,
        URL:       f.URL,
        Method:    f.Method,
        Payload:   model.JSON(f.Payload),
        Status:    f.Status,
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
}
```

2. **Database Seeder**
```go
// tests/seeder/seeder.go
package seeder

type Seeder struct {
    db *gorm.DB
}

func (s *Seeder) SeedEndpoints(count int) error {
    for i := 0; i < count; i++ {
        endpoint := factories.NewEndpointFactory().Build()
        if err := s.db.Create(endpoint).Error; err != nil {
            return err
        }
    }
    return nil
}
```

## Testing Best Practices

1. **Test Naming Convention**
   - Use descriptive test names
   - Include scenario in name
   - Use `TestFunctionName_Scenario_ExpectedResult`

2. **Test Structure (AAA)**
   - Arrange: Setup test data and mocks
   - Act: Execute the function being tested
   - Assert: Verify the results

3. **Test Isolation**
   - Each test should be independent
   - Use clean fixtures for each test
   - No shared state between tests

4. **Mock Usage**
   - Mock only external dependencies
   - Verify mock interactions
   - Use consistent mock expectations

---

## Deliverables

1. **Test Suite**
   - Unit tests for all components
   - Integration tests for workflows
   - Test utilities and helpers
   - Test fixtures and data

2. **CI/CD Configuration**
   - Test pipeline configuration
   - Coverage reporting setup
   - Test result notifications
   - Performance test jobs

3. **Test Documentation**
   - Test strategy document
   - Test execution guide
   - Coverage report analysis
   - Known test flakiness

---

## Checklists

### Test Coverage Checklist
- [ ] All services tested
- [ ] All repositories tested
- [ ] All handlers tested
- [ ] Error paths tested
- [ ] Edge cases covered

### Test Quality Checklist
- [ ] No code duplication in tests
- [ ] Tests maintainable
- [ ] Descriptive assertions
- [ ] Proper test isolation
- [ ] Test data cleanup working

---

*Reviewer: Lead QA Engineer*  
* Approved by: Engineering Manager, Tech Lead*  
* Completion Date: Expected 2025-03-24*