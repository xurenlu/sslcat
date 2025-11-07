# Redis 模板

Redis 7 高性能内存数据库，支持缓存、消息队列、会话存储等场景。

## 功能特性

- ✅ Redis 7 缓存数据库
- ✅ AOF 持久化支持
- ✅ 密码保护
- ✅ 健康检查支持

## 默认凭证

部署后，系统会自动生成以下凭证：

- **密码**: 自动生成（24位随机密码）

## 连接信息

- **主机**: `redis` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `6379`
- **持久化**: AOF 已启用

## 数据持久化

数据存储在 Docker volume `redis_data` 中，AOF 持久化已启用，确保数据安全。

## 管理命令

```bash
# 查看日志
docker-compose -f docker-compose.yml -p sslcat-{app_name} logs -f redis

# 进入 Redis 命令行
docker-compose -f docker-compose.yml -p sslcat-{app_name} exec redis redis-cli -a {password}

# 查看 Redis 信息
docker-compose -f docker-compose.yml -p sslcat-{app_name} exec redis redis-cli -a {password} INFO
```

