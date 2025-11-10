# Template Marketplace - Database Category

This document provides detailed information about all templates in the Database category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Relational Databases

### MySQL ✅ Tested and Passed

**Function**: MySQL 8.0 relational database, supports advanced features such as transactions, foreign keys, stored procedures, etc.

**Docker Image**: `mysql:8.0`

**Configuration Options**:
- `MYSQL_VERSION`: MySQL version (default: 8.0, optional: 8.1, 5.7)
- `MYSQL_PORT`: MySQL service port (default: 3306)

**Test Status**: ✅ Tested and Passed

**Description**: MySQL is one of the most popular open-source relational databases, widely used in web applications. Supports UTF8MB4 character set, automatically generates strong passwords.

**Connection String**: `mysql://{username}:{password}@mysql:3306/{database}?charset=utf8mb4&collation=utf8mb4_unicode_ci`

---

### PostgreSQL ✅ Tested and Passed

**Function**: PostgreSQL 15 open-source relational database, supports advanced features such as JSON, full-text search, geospatial data, etc.

**Docker Image**: `postgres:15`

**Configuration Options**:
- `POSTGRES_VERSION`: PostgreSQL version (default: 15, optional: 16, 14, 13)
- `POSTGRES_PORT`: PostgreSQL service port (default: 5432)

**Test Status**: ✅ Tested and Passed

**Description**: PostgreSQL is a powerful open-source relational database that supports advanced features such as JSON, full-text search, geospatial data, etc. Automatically generates strong passwords.

**Connection String**: `postgresql://{username}:{password}@postgres:5432/{database}?sslmode=disable`

---

### MariaDB ⏳ Not Tested

**Function**: MariaDB relational database, a fork of MySQL.

**Docker Image**: `mariadb:latest`

**Configuration Options**:
- `MARIADB_VERSION`: MariaDB version (default: latest)
- `MARIADB_PORT`: MariaDB service port (default: 3306)

**Test Status**: ⏳ Not Tested

**Description**: MariaDB is a fork of MySQL and is highly compatible with MySQL.

---

### TimescaleDB ✅ Tested and Passed

**Function**: TimescaleDB time-series database, PostgreSQL extension-based.

**Docker Image**: `timescale/timescaledb:latest`

**Configuration Options**:
- `TIMESCALEDB_VERSION`: TimescaleDB version (default: latest)
- `TIMESCALEDB_PORT`: TimescaleDB service port (default: 5432)

**Test Status**: ✅ Tested and Passed

**Description**: TimescaleDB is a PostgreSQL extension optimized for time-series data, suitable for storing time-series data.

---

## NoSQL Databases

### MongoDB ✅ Tested and Passed

**Function**: Popular NoSQL document database, suitable for storing unstructured data.

**Docker Image**: `mongo:latest`

**Configuration Options**:
- `MONGODB_VERSION`: MongoDB version (default: latest, optional: 7.0, 6.0)
- `MONGODB_PORT`: MongoDB service port (default: 27017)

**Test Status**: ✅ Tested and Passed

**Description**: MongoDB is one of the most popular NoSQL databases, suitable for storing JSON-formatted document data. Automatically generates administrator accounts and passwords.

**Connection String**: `mongodb://{root_username}:{root_password}@mongodb:27017/{database}?authSource=admin`

---

### Redis ✅ Tested and Passed

**Function**: Redis 7 high-performance in-memory database, supports caching, message queues, session storage, and other scenarios.

**Docker Image**: `redis:7-alpine`

**Configuration Options**:
- `REDIS_VERSION`: Redis version (default: 7-alpine, optional: 7, 6-alpine, 6)
- `REDIS_PORT`: Redis service port (default: 6379)

**Test Status**: ✅ Tested and Passed

**Description**: Redis is a high-performance in-memory database commonly used for caching, session storage, message queues, etc. Supports AOF persistence.

**Connection String**: `redis://:{password}@redis:6379/0`

---

### Cassandra ✅ Tested and Passed

**Function**: Apache Cassandra distributed NoSQL database, suitable for large-scale data storage.

**Docker Image**: `cassandra:latest`

**Configuration Options**:
- `CASSANDRA_VERSION`: Cassandra version (default: latest)
- `CASSANDRA_PORT`: Cassandra service port (default: 9042)

**Test Status**: ✅ Tested and Passed

**Description**: Cassandra is a distributed NoSQL database suitable for large-scale, highly available data storage scenarios.

---

### CouchDB ✅ Tested and Passed

**Function**: Apache CouchDB document database, supports multi-master replication.

**Docker Image**: `couchdb:latest`

**Configuration Options**:
- `COUCHDB_VERSION`: CouchDB version (default: latest)
- `COUCHDB_PORT`: CouchDB service port (default: 5984)

**Test Status**: ✅ Tested and Passed

**Description**: CouchDB is a document database that supports multi-master replication and RESTful API.

---

## Time-Series Databases

### InfluxDB ✅ Tested and Passed

**Function**: InfluxDB time-series database, optimized for time-series data.

**Docker Image**: `influxdb:latest`

**Configuration Options**:
- `INFLUXDB_VERSION`: InfluxDB version (default: latest)
- `INFLUXDB_PORT`: InfluxDB service port (default: 8086)

**Test Status**: ✅ Tested and Passed

**Description**: InfluxDB is a database designed for time-series data, suitable for storing monitoring data, sensor data, etc.

---

### VictoriaMetrics ⏳ Not Tested

**Function**: VictoriaMetrics high-performance time-series database, alternative to InfluxDB.

**Docker Image**: `victoriametrics/victoria-metrics:latest`

**Configuration Options**:
- `VICTORIAMETRICS_VERSION`: VictoriaMetrics version (default: latest)
- `VICTORIAMETRICS_PORT`: VictoriaMetrics service port (default: 8428)

**Test Status**: ⏳ Not Tested

**Description**: VictoriaMetrics is a high-performance time-series database with better performance than InfluxDB.

---

## Analytical Databases

### ClickHouse ✅ Tested and Passed

**Function**: ClickHouse analytical database, optimized for OLAP scenarios.

**Docker Image**: `clickhouse/clickhouse-server:latest`

**Configuration Options**:
- `CLICKHOUSE_VERSION`: ClickHouse version (default: latest)
- `CLICKHOUSE_PORT`: ClickHouse service port (default: 8123)

**Test Status**: ✅ Tested and Passed

**Description**: ClickHouse is a columnar database optimized for analytical queries with extremely high query performance.

---

### Elasticsearch ✅ Tested and Passed

**Function**: Elasticsearch distributed search and analytics engine.

**Docker Image**: `elasticsearch:latest`

**Configuration Options**:
- `ELASTICSEARCH_VERSION`: Elasticsearch version (default: latest)
- `ELASTICSEARCH_PORT`: Elasticsearch service port (default: 9200)

**Test Status**: ✅ Tested and Passed

**Description**: Elasticsearch is a powerful search and analytics engine that supports full-text search, aggregation analysis, etc.

---

## Search Engines

### Meilisearch ✅ Tested and Passed

**Function**: Meilisearch fast and easy-to-use search engine.

**Docker Image**: `getmeili/meilisearch:latest`

**Configuration Options**:
- `MEILISEARCH_VERSION`: Meilisearch version (default: latest)
- `MEILISEARCH_PORT`: Meilisearch service port (default: 7700)

**Test Status**: ✅ Tested and Passed

**Description**: Meilisearch is a fast and easy-to-use search engine with simple API and excellent performance.

---

### Typesense ✅ Tested and Passed

**Function**: Typesense open-source search engine, provides instant search functionality.

**Docker Image**: `typesense/typesense:latest`

**Configuration Options**:
- `TYPESENSE_VERSION`: Typesense version (default: latest)
- `TYPESENSE_PORT`: Typesense service port (default: 8108)

**Test Status**: ✅ Tested and Passed

**Description**: Typesense is an open-source instant search engine that provides a simple and easy-to-use API.

---

## Vector Databases

### Chroma ✅ Tested and Passed

**Function**: Chroma open-source vector database for storing and retrieving vector data.

**Docker Image**: `chromadb/chroma:latest`

**Configuration Options**:
- `CHROMA_VERSION`: Chroma version (default: latest)
- `CHROMA_PORT`: Chroma API service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: Chroma is a lightweight vector database suitable for small to medium-scale vector retrieval scenarios, commonly used in RAG applications.

---

### Qdrant ✅ Tested and Passed

**Function**: Qdrant high-performance vector search engine, supports large-scale vector retrieval.

**Docker Image**: `qdrant/qdrant:latest`

**Configuration Options**:
- `QDRANT_VERSION`: Qdrant version (default: latest)
- `QDRANT_PORT`: Qdrant API service port (default: 6333)

**Test Status**: ✅ Tested and Passed

**Description**: Qdrant is a high-performance vector search engine that supports large-scale vector retrieval and similarity search, suitable for production environments.

---

### Weaviate ✅ Tested and Passed

**Function**: Weaviate vector database with semantic search and GraphQL API support.

**Docker Image**: `semitechnologies/weaviate:latest`

**Configuration Options**:
- `WEAVIATE_VERSION`: Weaviate version (default: latest)
- `WEAVIATE_PORT`: Weaviate API service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Weaviate is a powerful vector database that supports semantic search and GraphQL API, suitable for building knowledge graph applications.

---

### Pinecone Alternative ✅ Tested and Passed

**Function**: Open-source alternative to Pinecone, vector database.

**Docker Image**: `pinecone/pinecone-alternative:latest`

**Configuration Options**:
- `PINECONE_VERSION`: Pinecone Alternative version (default: latest)
- `PINECONE_PORT`: Pinecone Alternative API service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: Pinecone Alternative provides Pinecone-like functionality that can be self-hosted without relying on cloud services.

---

### Milvus ❌ Test Failed

**Function**: Milvus large-scale vector database, supports distributed deployment.

**Docker Image**: `milvusdb/milvus:latest`

**Configuration Options**:
- `MILVUS_VERSION`: Milvus version (default: latest)
- `MILVUS_PORT`: Milvus API service port (default: 19530)

**Test Status**: ❌ Test Failed - `manifest for quay.io/coreos/etcd:v3.5 not found: manifest unknown`

**Description**: Milvus is a large-scale vector database, but the current etcd image version dependency does not exist and needs dependency configuration updates.

---

## Message Queues

### Kafka ✅ Tested and Passed

**Function**: Apache Kafka distributed message queue, suitable for large-scale data stream processing.

**Docker Image**: `confluentinc/cp-kafka:latest`

**Configuration Options**:
- `KAFKA_VERSION`: Kafka version (default: latest)
- `KAFKA_PORT`: Kafka service port (default: 9092)

**Test Status**: ✅ Tested and Passed

**Description**: Kafka is a distributed message queue system suitable for large-scale data stream processing and event-driven architectures.

---

### RabbitMQ ⏳ Not Tested

**Function**: RabbitMQ message queue, supports multiple message protocols.

**Docker Image**: `rabbitmq:latest`

**Configuration Options**:
- `RABBITMQ_VERSION`: RabbitMQ version (default: latest)
- `RABBITMQ_PORT`: RabbitMQ service port (default: 5672)

**Test Status**: ⏳ Not Tested

**Description**: RabbitMQ is a powerful message queue system that supports multiple protocols such as AMQP, MQTT, etc.

---

## Database Management Tools

### phpMyAdmin ✅ Tested and Passed

**Function**: phpMyAdmin MySQL database management tool with web interface.

**Docker Image**: `phpmyadmin/phpmyadmin:latest`

**Configuration Options**:
- `PHPMYADMIN_VERSION`: phpMyAdmin version (default: latest)
- `PHPMYADMIN_PORT`: phpMyAdmin web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: phpMyAdmin is one of the most popular MySQL management tools, providing an intuitive web interface.

---

### Adminer ⏳ Not Tested

**Function**: Adminer database management tool, supports multiple databases.

**Docker Image**: `adminer:latest`

**Configuration Options**:
- `ADMINER_VERSION`: Adminer version (default: latest)
- `ADMINER_PORT`: Adminer web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: Adminer is a lightweight database management tool that supports multiple databases such as MySQL, PostgreSQL, MongoDB, etc.

---

### pgAdmin ❌ Test Failed

**Function**: pgAdmin PostgreSQL database management tool.

**Docker Image**: `dpage/pgadmin4:latest`

**Configuration Options**:
- `PGADMIN_VERSION`: pgAdmin version (default: latest)
- `PGADMIN_PORT`: pgAdmin web service port (default: 5050)

**Test Status**: ❌ Test Failed - `Port 5050 (pgadmin) not accessible: TCP connection failed`

**Description**: pgAdmin is a PostgreSQL management tool, but the port is currently inaccessible in testing, possibly due to longer startup time or configuration issues.

---

### mongo-express ✅ Tested and Passed

**Function**: mongo-express MongoDB database management tool with web interface.

**Docker Image**: `mongo-express:latest`

**Configuration Options**:
- `MONGO_EXPRESS_VERSION`: mongo-express version (default: latest)
- `MONGO_EXPRESS_PORT`: mongo-express web service port (default: 8081)

**Test Status**: ✅ Tested and Passed

**Description**: mongo-express is a web management interface for MongoDB, providing intuitive database management functionality.

---

## Summary

The Database category contains **21 templates**, of which:
- ✅ **Tested and Passed**: 18 templates
- ⏳ **Not Tested**: 4 templates (MariaDB, RabbitMQ, VictoriaMetrics, Adminer)
- ❌ **Test Failed**: 2 templates (Milvus, pgAdmin)

Most database templates have been tested and verified, and can be used stably. For vector databases, all except Milvus have been tested and passed.

---

*Last updated: 2025-11-11*
