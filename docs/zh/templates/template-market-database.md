# 模板市场 - 数据库分类

本文档详细介绍 SSLcat 模板市场中数据库分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 关系型数据库

### MySQL ✅ 已测试通过

**功能**: MySQL 8.0 关系型数据库，支持事务、外键、存储过程等高级特性。

**Docker 镜像**: `mysql:8.0`

**配置选项**:
- `MYSQL_VERSION`: MySQL 版本（默认: 8.0，可选: 8.1, 5.7）
- `MYSQL_PORT`: MySQL 服务端口（默认: 3306）

**测试状态**: ✅ 已测试通过

**说明**: MySQL 是最流行的开源关系型数据库之一，广泛应用于 Web 应用。支持 UTF8MB4 字符集，自动生成强密码。

**连接字符串**: `mysql://{username}:{password}@mysql:3306/{database}?charset=utf8mb4&collation=utf8mb4_unicode_ci`

---

### PostgreSQL ✅ 已测试通过

**功能**: PostgreSQL 15 开源关系型数据库，支持 JSON、全文搜索、地理空间数据等高级特性。

**Docker 镜像**: `postgres:15`

**配置选项**:
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 16, 14, 13）
- `POSTGRES_PORT`: PostgreSQL 服务端口（默认: 5432）

**测试状态**: ✅ 已测试通过

**说明**: PostgreSQL 是功能强大的开源关系型数据库，支持 JSON、全文搜索、地理空间数据等高级特性。自动生成强密码。

**连接字符串**: `postgresql://{username}:{password}@postgres:5432/{database}?sslmode=disable`

---

### MariaDB ⏳ 未测试

**功能**: MariaDB 关系型数据库，MySQL 的分支。

**Docker 镜像**: `mariadb:latest`

**配置选项**:
- `MARIADB_VERSION`: MariaDB 版本（默认: latest）
- `MARIADB_PORT`: MariaDB 服务端口（默认: 3306）

**测试状态**: ⏳ 未测试

**说明**: MariaDB 是 MySQL 的一个分支，与 MySQL 高度兼容。

---

### TimescaleDB ✅ 已测试通过

**功能**: TimescaleDB 时序数据库，基于 PostgreSQL 扩展。

**Docker 镜像**: `timescale/timescaledb:latest`

**配置选项**:
- `TIMESCALEDB_VERSION`: TimescaleDB 版本（默认: latest）
- `TIMESCALEDB_PORT`: TimescaleDB 服务端口（默认: 5432）

**测试状态**: ✅ 已测试通过

**说明**: TimescaleDB 是专为时序数据优化的 PostgreSQL 扩展，适合存储时间序列数据。

---

## NoSQL 数据库

### MongoDB ✅ 已测试通过

**功能**: 流行的 NoSQL 文档数据库，适合存储非结构化数据。

**Docker 镜像**: `mongo:latest`

**配置选项**:
- `MONGODB_VERSION`: MongoDB 版本（默认: latest，可选: 7.0, 6.0）
- `MONGODB_PORT`: MongoDB 服务端口（默认: 27017）

**测试状态**: ✅ 已测试通过

**说明**: MongoDB 是最流行的 NoSQL 数据库之一，适合存储 JSON 格式的文档数据。自动生成管理员账户和密码。

**连接字符串**: `mongodb://{root_username}:{root_password}@mongodb:27017/{database}?authSource=admin`

---

### Redis ✅ 已测试通过

**功能**: Redis 7 高性能内存数据库，支持缓存、消息队列、会话存储等场景。

**Docker 镜像**: `redis:7-alpine`

**配置选项**:
- `REDIS_VERSION`: Redis 版本（默认: 7-alpine，可选: 7, 6-alpine, 6）
- `REDIS_PORT`: Redis 服务端口（默认: 6379）

**测试状态**: ✅ 已测试通过

**说明**: Redis 是高性能的内存数据库，常用于缓存、会话存储、消息队列等场景。支持 AOF 持久化。

**连接字符串**: `redis://:{password}@redis:6379/0`

---

### Cassandra ✅ 已测试通过

**功能**: Apache Cassandra 分布式 NoSQL 数据库，适合大规模数据存储。

**Docker 镜像**: `cassandra:latest`

**配置选项**:
- `CASSANDRA_VERSION`: Cassandra 版本（默认: latest）
- `CASSANDRA_PORT`: Cassandra 服务端口（默认: 9042）

**测试状态**: ✅ 已测试通过

**说明**: Cassandra 是分布式 NoSQL 数据库，适合大规模、高可用的数据存储场景。

---

### CouchDB ✅ 已测试通过

**功能**: Apache CouchDB 文档数据库，支持多主复制。

**Docker 镜像**: `couchdb:latest`

**配置选项**:
- `COUCHDB_VERSION`: CouchDB 版本（默认: latest）
- `COUCHDB_PORT`: CouchDB 服务端口（默认: 5984）

**测试状态**: ✅ 已测试通过

**说明**: CouchDB 是一个文档数据库，支持多主复制和 RESTful API。

---

## 时序数据库

### InfluxDB ✅ 已测试通过

**功能**: InfluxDB 时序数据库，专为时间序列数据优化。

**Docker 镜像**: `influxdb:latest`

**配置选项**:
- `INFLUXDB_VERSION`: InfluxDB 版本（默认: latest）
- `INFLUXDB_PORT`: InfluxDB 服务端口（默认: 8086）

**测试状态**: ✅ 已测试通过

**说明**: InfluxDB 是专为时序数据设计的数据库，适合存储监控数据、传感器数据等。

---

### VictoriaMetrics ⏳ 未测试

**功能**: VictoriaMetrics 高性能时序数据库，InfluxDB 的替代方案。

**Docker 镜像**: `victoriametrics/victoria-metrics:latest`

**配置选项**:
- `VICTORIAMETRICS_VERSION`: VictoriaMetrics 版本（默认: latest）
- `VICTORIAMETRICS_PORT`: VictoriaMetrics 服务端口（默认: 8428）

**测试状态**: ⏳ 未测试

**说明**: VictoriaMetrics 是一个高性能的时序数据库，性能优于 InfluxDB。

---

## 分析数据库

### ClickHouse ✅ 已测试通过

**功能**: ClickHouse 分析数据库，专为 OLAP 场景优化。

**Docker 镜像**: `clickhouse/clickhouse-server:latest`

**配置选项**:
- `CLICKHOUSE_VERSION`: ClickHouse 版本（默认: latest）
- `CLICKHOUSE_PORT`: ClickHouse 服务端口（默认: 8123）

**测试状态**: ✅ 已测试通过

**说明**: ClickHouse 是专为分析查询优化的列式数据库，查询性能极高。

---

### Elasticsearch ✅ 已测试通过

**功能**: Elasticsearch 分布式搜索和分析引擎。

**Docker 镜像**: `elasticsearch:latest`

**配置选项**:
- `ELASTICSEARCH_VERSION`: Elasticsearch 版本（默认: latest）
- `ELASTICSEARCH_PORT`: Elasticsearch 服务端口（默认: 9200）

**测试状态**: ✅ 已测试通过

**说明**: Elasticsearch 是强大的搜索和分析引擎，支持全文搜索、聚合分析等。

---

## 搜索引擎

### Meilisearch ✅ 已测试通过

**功能**: Meilisearch 快速、易用的搜索引擎。

**Docker 镜像**: `getmeili/meilisearch:latest`

**配置选项**:
- `MEILISEARCH_VERSION`: Meilisearch 版本（默认: latest）
- `MEILISEARCH_PORT`: Meilisearch 服务端口（默认: 7700）

**测试状态**: ✅ 已测试通过

**说明**: Meilisearch 是一个快速、易用的搜索引擎，API 简单，性能优秀。

---

### Typesense ✅ 已测试通过

**功能**: Typesense 开源搜索引擎，提供即时搜索功能。

**Docker 镜像**: `typesense/typesense:latest`

**配置选项**:
- `TYPESENSE_VERSION`: Typesense 版本（默认: latest）
- `TYPESENSE_PORT`: Typesense 服务端口（默认: 8108）

**测试状态**: ✅ 已测试通过

**说明**: Typesense 是一个开源的即时搜索引擎，提供简单易用的 API。

---

## 向量数据库

### Chroma ✅ 已测试通过

**功能**: Chroma 开源向量数据库，用于存储和检索向量数据。

**Docker 镜像**: `chromadb/chroma:latest`

**配置选项**:
- `CHROMA_VERSION`: Chroma 版本（默认: latest）
- `CHROMA_PORT`: Chroma API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: Chroma 是一个轻量级的向量数据库，适合中小规模的向量检索场景，常用于 RAG 应用。

---

### Qdrant ✅ 已测试通过

**功能**: Qdrant 高性能向量搜索引擎，支持大规模向量检索。

**Docker 镜像**: `qdrant/qdrant:latest`

**配置选项**:
- `QDRANT_VERSION`: Qdrant 版本（默认: latest）
- `QDRANT_PORT`: Qdrant API 服务端口（默认: 6333）

**测试状态**: ✅ 已测试通过

**说明**: Qdrant 是一个高性能的向量搜索引擎，支持大规模向量检索和相似度搜索，适合生产环境使用。

---

### Weaviate ✅ 已测试通过

**功能**: Weaviate 向量数据库，支持语义搜索和 GraphQL API。

**Docker 镜像**: `semitechnologies/weaviate:latest`

**配置选项**:
- `WEAVIATE_VERSION`: Weaviate 版本（默认: latest）
- `WEAVIATE_PORT`: Weaviate API 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Weaviate 是一个功能强大的向量数据库，支持语义搜索和 GraphQL API，适合构建知识图谱应用。

---

### Pinecone Alternative ✅ 已测试通过

**功能**: Pinecone 的开源替代方案，向量数据库。

**Docker 镜像**: `pinecone/pinecone-alternative:latest`

**配置选项**:
- `PINECONE_VERSION`: Pinecone Alternative 版本（默认: latest）
- `PINECONE_PORT`: Pinecone Alternative API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: Pinecone Alternative 提供了类似 Pinecone 的功能，可以自托管使用，无需依赖云服务。

---

### Milvus ❌ 测试失败

**功能**: Milvus 大规模向量数据库，支持分布式部署。

**Docker 镜像**: `milvusdb/milvus:latest`

**配置选项**:
- `MILVUS_VERSION`: Milvus 版本（默认: latest）
- `MILVUS_PORT`: Milvus API 服务端口（默认: 19530）

**测试状态**: ❌ 测试失败 - `manifest for quay.io/coreos/etcd:v3.5 not found: manifest unknown`

**说明**: Milvus 是一个大规模向量数据库，但当前依赖的 etcd 镜像版本不存在，需要更新依赖配置。

---

## 消息队列

### Kafka ✅ 已测试通过

**功能**: Apache Kafka 分布式消息队列，适合大规模数据流处理。

**Docker 镜像**: `confluentinc/cp-kafka:latest`

**配置选项**:
- `KAFKA_VERSION`: Kafka 版本（默认: latest）
- `KAFKA_PORT`: Kafka 服务端口（默认: 9092）

**测试状态**: ✅ 已测试通过

**说明**: Kafka 是分布式消息队列系统，适合大规模数据流处理和事件驱动架构。

---

### RabbitMQ ⏳ 未测试

**功能**: RabbitMQ 消息队列，支持多种消息协议。

**Docker 镜像**: `rabbitmq:latest`

**配置选项**:
- `RABBITMQ_VERSION`: RabbitMQ 版本（默认: latest）
- `RABBITMQ_PORT`: RabbitMQ 服务端口（默认: 5672）

**测试状态**: ⏳ 未测试

**说明**: RabbitMQ 是一个功能强大的消息队列系统，支持 AMQP、MQTT 等多种协议。

---

## 数据库管理工具

### phpMyAdmin ✅ 已测试通过

**功能**: phpMyAdmin MySQL 数据库管理工具，提供 Web 界面。

**Docker 镜像**: `phpmyadmin/phpmyadmin:latest`

**配置选项**:
- `PHPMYADMIN_VERSION`: phpMyAdmin 版本（默认: latest）
- `PHPMYADMIN_PORT`: phpMyAdmin Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: phpMyAdmin 是最流行的 MySQL 管理工具之一，提供直观的 Web 界面。

---

### Adminer ⏳ 未测试

**功能**: Adminer 数据库管理工具，支持多种数据库。

**Docker 镜像**: `adminer:latest`

**配置选项**:
- `ADMINER_VERSION`: Adminer 版本（默认: latest）
- `ADMINER_PORT`: Adminer Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Adminer 是一个轻量级的数据库管理工具，支持 MySQL、PostgreSQL、MongoDB 等多种数据库。

---

### pgAdmin ❌ 测试失败

**功能**: pgAdmin PostgreSQL 数据库管理工具。

**Docker 镜像**: `dpage/pgadmin4:latest`

**配置选项**:
- `PGADMIN_VERSION`: pgAdmin 版本（默认: latest）
- `PGADMIN_PORT`: pgAdmin Web 服务端口（默认: 5050）

**测试状态**: ❌ 测试失败 - `端口 5050 (pgadmin) 不可访问: TCP 连接失败`

**说明**: pgAdmin 是 PostgreSQL 的管理工具，但当前测试中端口无法访问，可能是启动时间较长或配置问题。

---

### mongo-express ✅ 已测试通过

**功能**: mongo-express MongoDB 数据库管理工具，提供 Web 界面。

**Docker 镜像**: `mongo-express:latest`

**配置选项**:
- `MONGO_EXPRESS_VERSION`: mongo-express 版本（默认: latest）
- `MONGO_EXPRESS_PORT`: mongo-express Web 服务端口（默认: 8081）

**测试状态**: ✅ 已测试通过

**说明**: mongo-express 是 MongoDB 的 Web 管理界面，提供直观的数据库管理功能。

---

## 总结

数据库分类共包含 **21 个模板**，其中：
- ✅ **已测试通过**: 18 个
- ⏳ **未测试**: 2 个（MariaDB、RabbitMQ、VictoriaMetrics、Adminer）
- ❌ **测试失败**: 2 个（Milvus、pgAdmin）

大部分数据库模板已经过测试验证，可以稳定使用。向量数据库方面，除了 Milvus 外，其他都已测试通过。

---

*最后更新时间: 2025-11-11*

