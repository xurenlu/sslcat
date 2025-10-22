# Spring Boot 集成

本指南展示如何将 SSLcat 与 Spring Boot 应用程序集成，实现分布式追踪、负载均衡和 SSL 终端。

## 概述

SSLcat 通过以下方式与 Spring Boot 应用程序提供无缝集成：
- **分布式追踪**: 自动追踪头部传播
- **负载均衡**: 多个后端实例
- **SSL 终端**: 安全的 HTTPS 通信
- **健康监控**: 应用程序健康检查

## 快速开始

### 1. 基础 Spring Boot 应用程序

创建一个简单的 Spring Boot 应用程序：

```java
@SpringBootApplication
@RestController
public class DemoApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
    
    @GetMapping("/api/hello")
    public ResponseEntity<Map<String, String>> hello() {
        return ResponseEntity.ok(Map.of(
            "message", "Hello from Spring Boot!",
            "timestamp", Instant.now().toString()
        ));
    }
}
```

### 2. SSLcat 配置

配置 SSLcat 代理到你的 Spring Boot 应用程序：

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443

proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        health_check:
          enabled: true
          path: "/actuator/health"
          interval: 30s
```

### 3. 启动服务

```bash
# 启动 Spring Boot 应用程序
mvn spring-boot:run

# 启动 SSLcat
sslcat -config sslcat.conf
```

## 分布式追踪集成

### 1. 添加依赖

在你的 `pom.xml` 中添加 OpenTelemetry 依赖：

```xml
<dependencies>
    <!-- Spring Boot Starter -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- OpenTelemetry Spring Boot Starter -->
    <dependency>
        <groupId>io.opentelemetry.instrumentation</groupId>
        <artifactId>opentelemetry-spring-boot-starter</artifactId>
        <version>1.32.0</version>
    </dependency>
    
    <!-- Actuator for health checks -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
</dependencies>
```

### 2. 配置追踪

在 `application.yml` 中添加追踪配置：

```yaml
# application.yml
spring:
  application:
    name: "spring-boot-demo"

management:
  tracing:
    sampling:
      probability: 1.0  # 开发环境100%采样
  endpoints:
    web:
      exposure:
        include: health,info,metrics,tracing

logging:
  level:
    io.opentelemetry: DEBUG
```

### 3. 创建追踪控制器

```java
@RestController
@RequestMapping("/api")
public class ApiController {
    
    private final Tracer tracer;
    
    public ApiController(Tracer tracer) {
        this.tracer = tracer;
    }
    
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable String id) {
        // Spring Boot 自动创建 span
        // SSLcat 追踪头部自动传播
        
        Span span = tracer.spanBuilder("get-user")
                .setAttribute("user.id", id)
                .startSpan();
        
        try (Scope scope = span.makeCurrent()) {
            // 你的业务逻辑
            User user = userService.findById(id);
            return ResponseEntity.ok(user);
        } finally {
            span.end();
        }
    }
    
    @PostMapping("/orders")
    public ResponseEntity<Order> createOrder(@RequestBody OrderRequest request) {
        Span span = tracer.spanBuilder("create-order")
                .setAttribute("order.amount", request.getAmount())
                .startSpan();
        
        try (Scope scope = span.makeCurrent()) {
            Order order = orderService.createOrder(request);
            return ResponseEntity.ok(order);
        } finally {
            span.end();
        }
    }
}
```

## 负载均衡配置

### 1. 多个后端实例

配置 SSLcat 在多个 Spring Boot 实例之间进行负载均衡：

```yaml
# sslcat.conf
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://localhost:8080"
          - "http://localhost:8081"
          - "http://localhost:8082"
        health_check:
          enabled: true
          path: "/actuator/health"
          interval: 30s
          timeout: 5s
```

### 2. Spring Boot 健康检查端点

确保你的 Spring Boot 应用程序有健康检查：

```java
@RestController
public class HealthController {
    
    @GetMapping("/actuator/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "timestamp", Instant.now().toString()
        ));
    }
}
```

## SSL 证书管理

### 1. 使用 Let's Encrypt 自动 SSL

```yaml
# sslcat.conf
ssl:
  certificates:
    - domain: "api.example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
```

### 2. 自定义 SSL 证书

```yaml
# sslcat.conf
ssl:
  certificates:
    - domain: "api.example.com"
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
```

## 监控和指标

### 1. Prometheus 指标

在你的 Spring Boot 应用程序中添加 Prometheus 指标：

```xml
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>
```

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: prometheus,health,info
  metrics:
    export:
      prometheus:
        enabled: true
```

### 2. 自定义指标

```java
@Component
public class CustomMetrics {
    
    private final Counter requestCounter;
    private final Timer requestTimer;
    
    public CustomMetrics(MeterRegistry meterRegistry) {
        this.requestCounter = Counter.builder("api.requests.total")
                .description("Total API requests")
                .register(meterRegistry);
        
        this.requestTimer = Timer.builder("api.request.duration")
                .description("API request duration")
                .register(meterRegistry);
    }
    
    public void incrementRequest() {
        requestCounter.increment();
    }
    
    public void recordRequestDuration(Duration duration) {
        requestTimer.record(duration);
    }
}
```

## Docker 部署

### 1. Spring Boot Dockerfile

```dockerfile
FROM openjdk:17-jdk-slim

WORKDIR /app
COPY target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 2. Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  sslcat:
    image: sslcat:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./sslcat.conf:/app/sslcat.conf
    depends_on:
      - spring-boot-app
    networks:
      - app-network

  spring-boot-app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

## 生产环境配置

### 1. SSLcat 生产配置

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false

proxy:
  rules:
    - domain: "api.example.com"
      target: "http://spring-boot-app:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "least_connections"
        backends:
          - "http://spring-boot-app-1:8080"
          - "http://spring-boot-app-2:8080"
          - "http://spring-boot-app-3:8080"
        health_check:
          enabled: true
          path: "/actuator/health"
          interval: 30s
          timeout: 5s

ssl:
  certificates:
    - domain: "api.example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
  tracing:
    enabled: true
    sample_rate: 0.1  # 生产环境10%采样
```

### 2. Spring Boot 生产配置

```yaml
# application-prod.yml
spring:
  application:
    name: "spring-boot-demo"

server:
  port: 8080

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  tracing:
    sampling:
      probability: 0.1  # 生产环境10%采样

logging:
  level:
    root: INFO
    com.example: DEBUG
```

## 故障排除

### 常见问题

1. **追踪头部未传播**
   - 确保 OpenTelemetry 正确配置
   - 检查 SSLcat 追踪配置
   - 验证 Spring Boot actuator 端点

2. **负载均衡不工作**
   - 检查后端健康端点
   - 验证 SSLcat 配置
   - 监控后端实例状态

3. **SSL 证书问题**
   - 验证域名配置
   - 检查 Let's Encrypt 速率限制
   - 监控证书过期

### 调试模式

启用调试日志：

```yaml
# sslcat.conf
server:
  debug: true

# application.yml
logging:
  level:
    io.opentelemetry: DEBUG
    org.springframework.web: DEBUG
```

## 最佳实践

1. **使用健康检查**: 实现适当的健康端点
2. **监控指标**: 设置 Prometheus 和 Grafana
3. **配置采样**: 为生产环境调整追踪采样
4. **安全通信**: 对所有通信使用 HTTPS
5. **负载测试**: 在负载下测试你的设置

## 相关文档

- [分布式追踪](../features/tracing.md)
- [负载均衡配置](../configuration/load-balancing.md)
- [SSL 证书](../configuration/ssl-certificates.md)
- [监控](../features/monitoring.md)

---

*本集成指南提供了成功部署 Spring Boot 应用程序与 SSLcat 所需的一切。*
