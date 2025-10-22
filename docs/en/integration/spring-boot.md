# Spring Boot Integration

This guide shows you how to integrate SSLcat with Spring Boot applications for distributed tracing, load balancing, and SSL termination.

## Overview

SSLcat provides seamless integration with Spring Boot applications through:
- **Distributed Tracing**: Automatic trace header propagation
- **Load Balancing**: Multiple backend instances
- **SSL Termination**: Secure HTTPS communication
- **Health Monitoring**: Application health checks

## Quick Start

### 1. Basic Spring Boot Application

Create a simple Spring Boot application:

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

### 2. SSLcat Configuration

Configure SSLcat to proxy to your Spring Boot application:

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

### 3. Start Services

```bash
# Start Spring Boot application
mvn spring-boot:run

# Start SSLcat
sslcat -config sslcat.conf
```

## Distributed Tracing Integration

### 1. Add Dependencies

Add OpenTelemetry dependencies to your `pom.xml`:

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

### 2. Configure Tracing

Add tracing configuration to `application.yml`:

```yaml
# application.yml
spring:
  application:
    name: "spring-boot-demo"

management:
  tracing:
    sampling:
      probability: 1.0  # 100% sampling for development
  endpoints:
    web:
      exposure:
        include: health,info,metrics,tracing

logging:
  level:
    io.opentelemetry: DEBUG
```

### 3. Create Traced Controllers

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
        // Spring Boot automatically creates spans
        // SSLcat trace headers are automatically propagated
        
        Span span = tracer.spanBuilder("get-user")
                .setAttribute("user.id", id)
                .startSpan();
        
        try (Scope scope = span.makeCurrent()) {
            // Your business logic here
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

## Load Balancing Configuration

### 1. Multiple Backend Instances

Configure SSLcat to load balance across multiple Spring Boot instances:

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

### 2. Spring Boot Health Endpoint

Ensure your Spring Boot application has health checks:

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

## SSL Certificate Management

### 1. Automatic SSL with Let's Encrypt

```yaml
# sslcat.conf
ssl:
  certificates:
    - domain: "api.example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
```

### 2. Custom SSL Certificates

```yaml
# sslcat.conf
ssl:
  certificates:
    - domain: "api.example.com"
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
```

## Monitoring and Metrics

### 1. Prometheus Metrics

Add Prometheus metrics to your Spring Boot application:

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

### 2. Custom Metrics

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

## Docker Deployment

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

## Production Configuration

### 1. SSLcat Production Config

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
    sample_rate: 0.1  # 10% sampling for production
```

### 2. Spring Boot Production Config

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
      probability: 0.1  # 10% sampling for production

logging:
  level:
    root: INFO
    com.example: DEBUG
```

## Troubleshooting

### Common Issues

1. **Trace Headers Not Propagated**
   - Ensure OpenTelemetry is properly configured
   - Check SSLcat tracing configuration
   - Verify Spring Boot actuator endpoints

2. **Load Balancing Not Working**
   - Check backend health endpoints
   - Verify SSLcat configuration
   - Monitor backend instance status

3. **SSL Certificate Issues**
   - Verify domain configuration
   - Check Let's Encrypt rate limits
   - Monitor certificate expiration

### Debug Mode

Enable debug logging:

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

## Best Practices

1. **Use Health Checks**: Implement proper health endpoints
2. **Monitor Metrics**: Set up Prometheus and Grafana
3. **Configure Sampling**: Adjust tracing sampling for production
4. **Secure Communication**: Use HTTPS for all communication
5. **Load Testing**: Test your setup under load

## Related Documentation

- [Distributed Tracing](../features/tracing.md)
- [Load Balancing Configuration](../configuration/load-balancing.md)
- [SSL Certificates](../configuration/ssl-certificates.md)
- [Monitoring](../features/monitoring.md)

---

*This integration guide provides everything you need to successfully deploy Spring Boot applications with SSLcat.*
