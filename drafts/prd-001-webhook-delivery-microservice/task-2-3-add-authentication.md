# Task 2.3: Add Authentication

**Task ID:** T2-003  
**Phase:** Phase 2 - Core Implementation  
**Duration:** 5 days  
**Assignee:** Backend Engineer & Security Engineer  
**Priority:** Critical  

## Overview

This task implements comprehensive authentication and authorization for the Webhook Delivery Microservice. This includes API authentication using JWT tokens, HMAC signature generation for outbound webhooks, webhook endpoint authentication using secrets, key rotation mechanisms, and integration with the company's identity management system.

## Prerequisites

- Core webhook service from Task 2.1 is operational
- Authentication service endpoint available
- Security requirements document approved
- Key management strategy defined
- JWT token format standardized

## Detailed Steps

### Step 1: Implement API Authentication (Day 1)
1. Set up JWT middleware
2. Integrate with identity provider
3. Implement token validation
4. Add role-based access control (RBAC)

```go
// internal/middleware/auth.go
package middleware

import (
    "context"
    "errors"
    "net/http"
    "strings"
    
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
)

type AuthMiddleware struct {
    jwtSecret        []byte
    identityProvider IdentityProvider
    logger           logger.Logger
}

type IdentityProvider interface {
    ValidateToken(ctx context.Context, token string) (*User, error)
    GetUserPermissions(ctx context.Context, userID string) ([]string, error)
}

type User struct {
    ID          string   `json:"id"`
    Username    string   `json:"username"`
    Email       string   `json:"email"`
    Roles       []string `json:"roles"`
    Permissions []string `json:"permissions"`
}

type Claims struct {
    UserID      string   `json:"sub"`
    Username    string   `json:"username"`
    Email       string   `json:"email"`
    Roles       []string `json:"roles"`
    Permissions []string `json:"permissions"`
    jwt.RegisteredClaims
}

func NewAuthMiddleware(
    jwtSecret string,
    identityProvider IdentityProvider,
    logger logger.Logger,
) *AuthMiddleware {
    return &AuthMiddleware{
        jwtSecret:        []byte(jwtSecret),
        identityProvider: identityProvider,
        logger:           logger,
    }
}

func (a *AuthMiddleware) RequireAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract token from Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Authorization header required",
            })
            c.Abort()
            return
        }
        
        // Remove "Bearer " prefix
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid authorization header format",
            })
            c.Abort()
            return
        }
        
        // Parse and validate token
        claims, err := a.parseToken(tokenString)
        if err != nil {
            a.logger.Warn("invalid token", "error", err)
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid token",
            })
            c.Abort()
            return
        }
        
        // Additional validation with identity provider
        user, err := a.identityProvider.ValidateToken(c.Request.Context(), tokenString)
        if err != nil {
            a.logger.Warn("token validation failed", "error", err)
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Token validation failed",
            })
            c.Abort()
            return
        }
        
        // Set user context
        c.Set("user", user)
        c.Set("userID", user.ID)
        c.Set("permissions", user.Permissions)
        
        c.Next()
    }
}

func (a *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        permissions, exists := c.Get("permissions")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Permissions not found",
            })
            c.Abort()
            return
        }
        
        userPerms, ok := permissions.([]string)
        if !ok {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Invalid permissions format",
            })
            c.Abort()
            return
        }
        
        // Check if user has required permission
        hasPermission := false
        for _, p := range userPerms {
            if p == permission || p == "admin" {
                hasPermission = true
                break
            }
        }
        
        if !hasPermission {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Insufficient permissions",
                "required": permission,
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}

func (a *AuthMiddleware) parseToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return a.jwtSecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, errors.New("invalid token claims")
}
```

### Step 2: Implement HMAC Signature Generation (Day 2)
1. Create signature generation service
2. Support multiple algorithms (SHA-256, SHA-512)
3. Add timestamp and nonce
4. Implement key versioning

```go
// internal/service/signature.go
package service

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
    "fmt"
    "hash"
    "time"
)

type SignatureService interface {
    GenerateHMAC(payload []byte, secret string, algorithm string) (string, error)
    GenerateTimestampedSignature(payload []byte, secret, algorithm string) (SignatureHeaders, error)
    VerifySignature(payload []byte, signature, secret, algorithm string) bool
}

type SignatureHeaders struct {
    Signature string `json:"x-webhook-signature"`
    Timestamp string `json:"x-webhook-timestamp"`
    Nonce     string `json:"x-webhook-nonce"`
    Version   string `json:"x-webhook-signature-version"`
}

type signatureService struct {
    logger logger.Logger
}

func NewSignatureService(logger logger.Logger) SignatureService {
    return &signatureService{
        logger: logger,
    }
}

func (s *signatureService) GenerateHMAC(payload []byte, secret string, algorithm string) (string, error) {
    var h hash.Hash
    
    switch strings.ToLower(algorithm) {
    case "sha256":
        h = hmac.New(sha256.New, []byte(secret))
    case "sha512":
        h = hmac.New(sha512.New, []byte(secret))
    default:
        return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
    }
    
    if _, err := h.Write(payload); err != nil {
        return "", fmt.Errorf("failed to write payload: %w", err)
    }
    
    signature := hex.EncodeToString(h.Sum(nil))
    return signature, nil
}

func (s *signatureService) GenerateTimestampedSignature(
    payload []byte,
    secret string,
    algorithm string,
) (SignatureHeaders, error) {
    // Generate timestamp
    timestamp := time.Now().Unix()
    
    // Generate nonce
    nonce := s.generateNonce()
    
    // Create signed payload with timestamp and nonce
    signedPayload := fmt.Sprintf("%s.%s.%s", string(payload), timestamp, nonce)
    
    // Generate HMAC signature
    signature, err := s.GenerateHMAC([]byte(signedPayload), secret, algorithm)
    if err != nil {
        return SignatureHeaders{}, err
    }
    
    return SignatureHeaders{
        Signature: fmt.Sprintf("%s=%s", algorithm, signature),
        Timestamp: fmt.Sprintf("%d", timestamp),
        Nonce:     nonce,
        Version:   "v1",
    }, nil
}

func (s *signatureService) VerifySignature(
    payload []byte,
    signature string,
    secret string,
    algorithm string,
) bool {
    // Parse signature format: algorithm=signature
    parts := strings.SplitN(signature, "=", 2)
    if len(parts) != 2 {
        return false
    }
    
    receivedAlgorithm := strings.ToLower(parts[0])
    if receivedAlgorithm != strings.ToLower(algorithm) {
        return false
    }
    
    expectedSignature, err := s.GenerateHMAC(payload, secret, algorithm)
    if err != nil {
        return false
    }
    
    return hmac.Equal([]byte(expectedSignature), []byte(parts[1]))
}

func (s *signatureService) generateNonce() string {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil {
        s.logger.Error("failed to generate nonce", "error", err)
        // Fallback to timestamp-based nonce
        return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
    }
    return hex.EncodeToString(b)
}

// Integration with webhook delivery
func (s *WebhookService) signWebhook(webhook *model.Webhook, endpoint *model.WebhookEndpoint) (map[string]string, error) {
    // Get signing key
    signingKey, err := s.keyService.GetCurrentKey(endpoint.ID)
    if err != nil {
        return nil, fmt.Errorf("failed to get signing key: %w", err)
    }
    
    // Generate signature headers
    signatureHeaders, err := s.signatureService.GenerateTimestampedSignature(
        webhook.Payload.RawMessage,
        signingKey.Secret,
        endpoint.SignatureAlgorithm,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to generate signature: %w", err)
    }
    
    // Create headers map
    headers := make(map[string]string)
    
    // Add custom headers
    if webhook.Headers != nil {
        for k, v := range webhook.Headers {
            headers[k] = v
        }
    }
    
    // Add signature headers
    headers["X-Webhook-Signature"] = signatureHeaders.Signature
    headers["X-Webhook-Timestamp"] = signatureHeaders.Timestamp
    headers["X-Webhook-Nonce"] = signatureHeaders.Nonce
    headers["X-Webhook-Signature-Version"] = signatureHeaders.Version
    headers["X-Webhook-ID"] = webhook.ID
    headers["X-Webhook-Key-ID"] = signingKey.ID
    
    return headers, nil
}
```

### Step 3: Implement Key Management (Day 2-3)
1. Create secret storage mechanism
2. Implement key rotation
3. Add key versioning
4. Secure key storage

```go
// internal/service/keymanagement.go
package service

import (
    "crypto/rand"
    "encoding/base64"
    "time"
)

type KeyService interface {
    CreateKey(ctx context.Context, endpointID string, algorithm string) (*SigningKey, error)
    GetCurrentKey(ctx context.Context, endpointID string) (*SigningKey, error)
    GetKey(ctx context.Context, keyID string) (*SigningKey, error)
    RotateKey(ctx context.Context, endpointID string) (*SigningKey, error)
    RevokeKey(ctx context.Context, keyID string) error
}

type SigningKey struct {
    ID        string    `json:"id"`
    EndpointIDstring   `json:"endpointId"`
    Secret    string    `json:"-"`
    Algorithm string    `json:"algorithm"`
    Version   int       `json:"version"`
    IsActive  bool      `json:"isActive"`
    CreatedAt time.Time `json:"createdAt"`
    ExpiresAt *time.Time `json:"expiresAt"`
    RevokedAt *time.Time `json:"revokedAt"`
}

type keyService struct {
    keyRepo repository.KeyRepository
    encryptor Encryptor
    logger   logger.Logger
}

func NewKeyService(
    keyRepo repository.KeyRepository,
    encryptor Encryptor,
    logger logger.Logger,
) KeyService {
    return &keyService{
        keyRepo:   keyRepo,
        encryptor: encryptor,
        logger:    logger,
    }
}

func (s *keyService) CreateKey(ctx context.Context, endpointID string, algorithm string) (*SigningKey, error) {
    // Generate random secret
    secret, err := s.generateSecret()
    if err != nil {
        return nil, fmt.Errorf("failed to generate secret: %w", err)
    }
    
    // Get current max version for endpoint
    maxVersion, err := s.keyRepo.GetMaxVersion(ctx, endpointID)
    if err != nil {
        return nil, fmt.Errorf("failed to get max version: %w", err)
    }
    
    // Encrypt secret
    encryptedSecret, err := s.encryptor.Encrypt(secret)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt secret: %w", err)
    }
    
    // Create key
    key := &SigningKey{
        ID:        uuid.New().String(),
        EndpointID: endpointID,
        Secret:    encryptedSecret,
        Algorithm: algorithm,
        Version:   maxVersion + 1,
        IsActive:  true,
        CreatedAt: time.Now(),
        ExpiresAt: nil, // Keys don't expire unless explicitly rotated
    }
    
    if err := s.keyRepo.Create(ctx, key); err != nil {
        return nil, fmt.Errorf("failed to save key: %w", err)
    }
    
    // Decrypt for return (only when needed)
    decryptedKey := *key
    decryptedKey.Secret = secret
    
    s.logger.Info("created new signing key",
        "keyId", key.ID,
        "endpointId", endpointID,
        "version", key.Version)
    
    return &decryptedKey, nil
}

func (s *keyService) RotateKey(ctx context.Context, endpointID string) (*SigningKey, error) {
    // Deactivate current key
    currentKey, err := s.GetCurrentKey(ctx, endpointID)
    if err != nil {
        return nil, fmt.Errorf("failed to get current key: %w", err)
    }
    
    // Mark old key as inactive
    if err := s.keyRepo.Deactivate(ctx, currentKey.ID); err != nil {
        return nil, fmt.Errorf("failed to deactivate key: %w", err)
    }
    
    // Create new key
    newKey, err := s.CreateKey(ctx, endpointID, currentKey.Algorithm)
    if err != nil {
        // Reactivate old key if rotation fails
        s.keyRepo.Activate(ctx, currentKey.ID)
        return nil, fmt.Errorf("failed to create new key: %w", err)
    }
    
    s.logger.Info("rotated signing key",
        "endpointId", endpointID,
        "oldKeyId", currentKey.ID,
        "newKeyId", newKey.ID)
    
    return newKey, nil
}

func (s *keyService) generateSecret() (string, error) {
    // Generate 64-byte random secret
    b := make([]byte, 64)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(b), nil
}

// Encryptor interface for secret encryption
type Encryptor interface {
    Encrypt(plaintext string) (string, error)
    Decrypt(ciphertext string) (string, error)
}

// AWS KMS implementation
type KMSEncryptor struct {
    kmsClient *kms.Client
    keyID     string
}

func (e *KMSEncryptor) Encrypt(plaintext string) (string, error) {
    input := &kms.EncryptInput{
        KeyId:     aws.String(e.keyID),
        Plaintext: []byte(plaintext),
    }
    
    result, err := e.kmsClient.Encrypt(context.Background(), input)
    if err != nil {
        return "", err
    }
    
    return base64.StdEncoding.EncodeToString(result.CiphertextBlob), nil
}

func (e *KMSEncryptor) Decrypt(ciphertext string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    
    input := &kms.DecryptInput{
        CiphertextBlob: data,
    }
    
    result, err := e.kmsClient.Decrypt(context.Background(), input)
    if err != nil {
        return "", err
    }
    
    return string(result.Plaintext), nil
}
```

### Step 4: Endpoint Authentication (Day 3-4)
1. Store endpoint secrets securely
2. Implement secret validation
3. Add endpoint authentication middleware
4. Support multiple auth methods

```go
// internal/service/endpoint_auth.go
package service

import (
    "context"
    "crypto/subtle"
    "encoding/base64"
    "strings"
)

type EndpointAuthService interface {
    ValidateRequest(ctx context.Context, webhookID string, headers map[string]string, body []byte) error
    GenerateAuthHeaders(ctx context.Context, endpointID string) (map[string]string, error)
}

type AuthType string

const (
    AuthTypeNone   AuthType = "none"
    AuthTypeHMAC   AuthType = "hmac"
    AuthTypeBearer AuthType = "bearer"
    AuthTypeBasic  AuthType = "basic"
)

type endpointAuthService struct {
    endpointRepo repository.EndpointRepository
    keyService   KeyService
    logger       logger.Logger
}

func NewEndpointAuthService(
    endpointRepo repository.EndpointRepository,
    keyService KeyService,
    logger logger.Logger,
) EndpointAuthService {
    return &endpointAuthService{
        endpointRepo: endpointRepo,
        keyService:   keyService,
        logger:       logger,
    }
}

func (s *endpointAuthService) ValidateRequest(
    ctx context.Context,
    webhookID string,
    headers map[string]string,
    body []byte,
) error {
    // Get endpoint details for this webhook
    webhook, err := s.webhookRepo.GetByID(ctx, webhookID)
    if err != nil {
        return fmt.Errorf("failed to get webhook: %w", err)
    }
    
    endpoint, err := s.endpointRepo.GetByID(ctx, webhook.EndpointID)
    if err != nil {
        return fmt.Errorf("failed to get endpoint: %w", err)
    }
    
    // Check if authentication is required
    if endpoint.AuthType == AuthTypeNone {
        return nil
    }
    
    switch endpoint.AuthType {
    case AuthTypeHMAC:
        return s.validateHMACAuth(ctx, endpoint, headers, body)
    case AuthTypeBearer:
        return s.validateBearerAuth(ctx, endpoint, headers)
    case AuthTypeBasic:
        return s.validateBasicAuth(ctx, endpoint, headers)
    default:
        return errors.New("unsupported authentication type")
    }
}

func (s *endpointAuthService) validateHMACAuth(
    ctx context.Context,
    endpoint *model.WebhookEndpoint,
    headers map[string]string,
    body []byte,
) error {
    // Extract signature
    signature, ok := headers["X-Webhook-Signature"]
    if !ok {
        return errors.New("missing signature header")
    }
    
    // Extract timestamp
    timestamp, ok := headers["X-Webhook-Timestamp"]
    if !ok {
        return errors.New("missing timestamp header")
    }
    
    // Verify timestamp is recent (prevent replay attacks)
    ts, err := strconv.ParseInt(timestamp, 10, 64)
    if err != nil {
        return errors.New("invalid timestamp format")
    }
    
    if time.Since(time.Unix(ts, 0)) > 5*time.Minute {
        return errors.New("timestamp too old")
    }
    
    // Get signing key
    keyID, ok := headers["X-Webhook-Key-ID"]
    var key *SigningKey
    if ok {
        // Try to get specific key
        key, err = s.keyService.GetKey(ctx, keyID)
        if err != nil {
            s.logger.Warn("key not found, falling back to current key",
                "keyId", keyID,
                "error", err)
        }
    }
    
    if key == nil {
        // Get current key
        key, err = s.keyService.GetCurrentKey(ctx, endpoint.ID)
        if err != nil {
            return fmt.Errorf("failed to get signing key: %w", err)
        }
    }
    
    // Recreate signed payload
    nonce := headers["X-Webhook-Nonce"]
    signedPayload := fmt.Sprintf("%s.%s.%s", string(body), timestamp, nonce)
    
    // Verify signature
    valid := s.signatureService.VerifySignature(
        []byte(signedPayload),
        signature,
        key.Secret,
        key.Algorithm,
    )
    
    if !valid {
        return errors.New("invalid signature")
    }
    
    return nil
}

func (s *endpointAuthService) validateBearerAuth(
    ctx context.Context,
    endpoint *model.WebhookEndpoint,
    headers map[string]string,
) error {
    authHeader, ok := headers["Authorization"]
    if !ok {
        return errors.New("missing authorization header")
    }
    
    if !strings.HasPrefix(authHeader, "Bearer ") {
        return errors.New("invalid authorization format")
    }
    
    token := strings.TrimPrefix(authHeader, "Bearer ")
    
    // Compare with stored token (using constant-time comparison)
    if subtle.ConstantTimeCompare(
        []byte(token),
        []byte(endpoint.AuthToken),
    ) != 1 {
        return errors.New("invalid bearer token")
    }
    
    return nil
}

func (s *endpointAuthService) validateBasicAuth(
    ctx context.Context,
    endpoint *model.WebhookEndpoint,
    headers map[string]string,
) error {
    authHeader, ok := headers["Authorization"]
    if !ok {
        return errors.New("missing authorization header")
    }
    
    if !strings.HasPrefix(authHeader, "Basic ") {
        return errors.New("invalid authorization format")
    }
    
    encoded := strings.TrimPrefix(authHeader, "Basic ")
    decoded, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil {
        return errors.New("invalid base64 encoding")
    }
    
    credentials := strings.SplitN(string(decoded), ":", 2)
    if len(credentials) != 2 {
        return errors.New("invalid credentials format")
    }
    
    // Compare with stored credentials
    if subtle.ConstantTimeCompare(
        []byte(credentials[0]),
        []byte(endpoint.AuthUsername),
    ) != 1 || subtle.ConstantTimeCompare(
        []byte(credentials[1]),
        []byte(endpoint.AuthPassword),
    ) != 1 {
        return errors.New("invalid credentials")
    }
    
    return nil
}

func (s *endpointAuthService) GenerateAuthHeaders(
    ctx context.Context,
    endpointID string,
) (map[string]string, error) {
    endpoint, err := s.endpointRepo.GetByID(ctx, endpointID)
    if err != nil {
        return nil, fmt.Errorf("failed to get endpoint: %w", err)
    }
    
    headers := make(map[string]string)
    
    switch endpoint.AuthType {
    case AuthTypeBearer:
        headers["Authorization"] = "Bearer " + endpoint.AuthToken
    case AuthTypeBasic:
        credentials := base64.StdEncoding.EncodeToString(
            []byte(endpoint.AuthUsername + ":" + endpoint.AuthPassword),
        )
        headers["Authorization"] = "Basic " + credentials
    }
    
    return headers, nil
}
```

### Step 5: Add API Permissions (Day 4)
1. Define permission model
2. Implement permission checking
3. Add RBAC middleware
4. Create permission management API

```go
// internal/permissions/permissions.go
package permissions

const (
    // Webhook permissions
    WebhookCreate = "webhook:create"
    WebhookRead   = "webhook:read"
    WebhookUpdate = "webhook:update"
    WebhookDelete = "webhook:delete"
    WebhookRetry  = "webhook:retry"
    
    // Endpoint permissions
    EndpointCreate = "endpoint:create"
    EndpointRead   = "endpoint:read"
    EndpointUpdate = "endpoint:update"
    EndpointDelete = "endpoint:delete"
    
    // Admin permissions
    AdminKeysManage = "admin:keys:manage"
    AdminMetrics    = "admin:metrics"
    AdminConfig     = "admin:config"
)

var (
    AllPermissions = []string{
        WebhookCreate, WebhookRead, WebhookUpdate, WebhookDelete, WebhookRetry,
        EndpointCreate, EndpointRead, EndpointUpdate, EndpointDelete,
        AdminKeysManage, AdminMetrics, AdminConfig,
    }
    
    RolePermissions = map[string][]string{
        "admin": AllPermissions,
        "developer": {
            WebhookCreate, WebhookRead, WebhookUpdate, WebhookDelete, WebhookRetry,
            EndpointCreate, EndpointRead, EndpointUpdate, EndpointDelete,
        },
        "viewer": {
            WebhookRead,
            EndpointRead,
        },
        "service": {
            WebhookCreate, WebhookRead, WebhookUpdate,
        },
    }
)

// Apply to API routes
func (h *WebhookHandler) setupRoutes(r *gin.RouterGroup) {
    // Public endpoints
    r.GET("/health", h.HealthCheck)
    
    // Authenticated endpoints
    auth := r.Group("/")
    auth.Use(h.authMiddleware.RequireAuth())
    {
        // Webhook endpoints
        webhooks := auth.Group("/webhooks")
        webhooks.Use(h.authMiddleware.RequirePermission(WebhookRead))
        {
            webhooks.POST("", h.authMiddleware.RequirePermission(WebhookCreate), h.SubmitWebhook)
            webhooks.GET("", h.ListWebhooks)
            webhooks.GET("/:id", h.GetWebhook)
            webhooks.PUT("/:id", h.authMiddleware.RequirePermission(WebhookUpdate), h.UpdateWebhook)
            webhooks.DELETE("/:id", h.authMiddleware.RequirePermission(WebhookDelete), h.DeleteWebhook)
            webhooks.POST("/:id/retry", h.authMiddleware.RequirePermission(WebhookRetry), h.RetryWebhook)
        }
        
        // Endpoint endpoints
        endpoints := auth.Group("/endpoints")
        endpoints.Use(h.authMiddleware.RequirePermission(EndpointRead))
        {
            endpoints.POST("", h.authMiddleware.RequirePermission(EndpointCreate), h.CreateEndpoint)
            endpoints.GET("", h.ListEndpoints)
            endpoints.GET("/:id", h.GetEndpoint)
            endpoints.PUT("/:id", h.authMiddleware.RequirePermission(EndpointUpdate), h.UpdateEndpoint)
            endpoints.DELETE("/:id", h.authMiddleware.RequirePermission(EndpointDelete), h.DeleteEndpoint)
        }
        
        // Admin endpoints
        admin := auth.Group("/admin")
        admin.Use(h.authMiddleware.RequirePermission(AdminMetrics))
        {
            admin.GET("/metrics", h.GetMetrics)
            
            // Key management requires special permission
            keys := admin.Group("/keys")
            keys.Use(h.authMiddleware.RequirePermission(AdminKeysManage))
            {
                keys.POST("", h.CreateSigningKey)
                keys.POST("/:id/rotate", h.RotateSigningKey)
                keys.DELETE("/:id", h.RevokeSigningKey)
            }
        }
    }
}
```

### Step 6: Security Hardening (Day 5)
1. Add rate limiting for auth endpoints
2. Implement audit logging
3. Add CORS configuration
4. Security headers middleware

```go
// internal/middleware/security.go
package middleware

import (
    "net/http"
    "strings"
    "time"
    
    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "golang.org/x/time/rate"
)

type SecurityMiddleware struct {
    limiter *rate.Limiter
    logger  logger.Logger
}

func NewSecurityMiddleware(requestsPerSecond float64, logger logger.Logger) *SecurityMiddleware {
    return &SecurityMiddleware{
        limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), 10),
        logger:  logger,
    }
}

func (s *SecurityMiddleware) RateLimit() gin.HandlerFunc {
    return func(c *gin.Context) {
        if !s.limiter.Allow() {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "Rate limit exceeded",
            })
            c.Abort()
            return
        }
        c.Next()
    }
}

func (s *SecurityMiddleware) CORS() gin.HandlerFunc {
    config := cors.DefaultConfig()
    config.AllowOrigins = []string{
        "https://dashboard.company.com",
        "https://admin.company.com",
    }
    config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    config.AllowHeaders = []string{
        "Origin",
        "Content-Type",
        "Accept",
        "Authorization",
        "X-Request-ID",
    }
    config.ExposeHeaders = []string{"X-Request-ID"}
    config.AllowCredentials = true
    config.MaxAge = 12 * time.Hour
    
    return cors.New(config)
}

func (s *SecurityMiddleware) SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Prevent XSS
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        
        // HSTS
        if !strings.HasPrefix(c.Request.URL.Scheme, "https") {
            c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        }
        
        // Content Security Policy
        c.Header("Content-Security-Policy", "default-src 'self'")
        
        // Referrer Policy
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        
        c.Next()
    }
}

// Audit logging middleware
func (s *SecurityMiddleware) AuditLog() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path
        raw := c.Request.URL.RawQuery
        
        // Process request
        c.Next()
        
        // Calculate latency
        latency := time.Since(start)
        
        // Get user info if available
        userID, _ := c.Get("userID")
        
        // Log request
        s.logger.Info("api_request",
            "method", c.Request.Method,
            "path", path,
            "query", raw,
            "status", c.Writer.Status(),
            "latency", latency,
            "ip", c.ClientIP(),
            "userAgent", c.Request.UserAgent(),
            "userID", userID,
            "requestID", c.GetString("requestID"),
        )
    }
}
```

## Acceptance Criteria

### Must-Have
- [ ] API endpoints require valid JWT tokens
- [ ] HMAC signatures generated for all outgoing webhooks
- [ ] Endpoint authentication working for all auth types
- [ ] Key rotation mechanism implemented
- [ ] RBAC permissions enforced
- [ ] All secret data encrypted at rest

### Should-Have
- [ ] Audit logging for all actions
- [ ] Rate limiting on sensitive endpoints
- [ ] CORS properly configured
- [ ] Security headers in all responses
- [ ] Key rotation automation

### Could-Have
- [ ] IP-based access restrictions
- [ ] Certificate-based authentication
- [ ] API key rotation
- [ ] Webhook payload encryption

## Security Requirements

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Authenticationvia JWT |middleware implemented |✓|
| HTTPS only |security headers |✓|
| Secret encryption |KMS/AWS secrets |✓|
| Audit logging |audit middleware |✓|
| Input validation |bind.validate |✓|
| Rate limiting |token bucket |✓|

## Testing Requirements

1. **Security Tests**
   - Attempt access without token
   - Use invalid/expired tokens
   - Test with insufficient permissions
   - Verify signature correctness

2. **Penetration Tests**
   - SQL injection attempts
   - XSS injection attempts
   - Authentication bypass
   - Rate limiting bypass

3. **Compliance Tests**
   - GDPR compliance
   - SOC 2 controls
   - PCI DSS requirements (if applicable)

## Deliverables

1. **Authentication Middleware**
   - JWT validation
   - RBAC enforcement
   - Permission checking

2. **Signature Service**
   - HMAC generation
   - Signature verification
   - Algorithm support

3. **Key Management**
   - Secure key storage
   - Rotation logic
   - Versioning system

4. **Security Documentation**
   - Authentication guide
   - Security best practices
   - Threat model

---

## Checklists

### Security Review Checklist
- [ ] No hardcoded secrets
- [ ] All secrets encrypted
- [ ] Proper error messages (no info leak)
- [ ] Rate limiting tested
- [ ] Input validation complete

### Deployment Checklist
- [ ] JWT secret configured
- [ ] KMS key permissions set
- [ ] Security headers enabled
- [ ] Monitoring for failed auth attempts
- [ ] Audit log storage configured

---

*Reviewer: Security Engineer, Senior Backend Engineer*  
* Approved by: CISO, Engineering Lead*  
* Completion Date: Expected 2025-03-10*