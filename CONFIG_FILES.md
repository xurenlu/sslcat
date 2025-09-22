# SSLcat 配置文件说明

## 配置文件组织

SSLcat 提供了三个不同级别的配置文件，以满足不同用户的需求：

### 1. 基础配置文件
**文件**: `sslcat.conf.example`
**用途**: 基础 SSL 代理功能
**适用用户**: 普通用户、初学者

**包含功能**:
- SSL 证书管理
- 反向代理
- 基础安全设置
- 静态站点托管
- PHP 站点支持

### 2. 高级配置文件  
**文件**: `sslcat-advanced.conf.example`
**用途**: 高级功能配置
**适用用户**: 企业用户、高级用户

**包含功能**:
- 集群管理
- DNS 提供商集成
- CDN 缓存
- 高级安全功能
- 监控和统计

### 3. Runner 配置文件
**文件**: `sslcat-runners.conf.example`
**用途**: 应用运行和管理功能
**适用用户**: 开发者、DevOps 工程师

**包含功能**:
- Local Runner（本地程序执行）
- Docker Runner（容器化执行）
- Git 服务器（代码管理）
- 运行时检测

## 配置文件选择指南

### 新手用户
```bash
# 使用基础配置
cp sslcat.conf.example sslcat.conf
```

### 企业用户
```bash
# 使用高级配置
cp sslcat-advanced.conf.example sslcat.conf
```

### 开发者用户
```bash
# 使用 Runner 配置
cp sslcat-runners.conf.example sslcat.conf
```

### 自定义配置
```bash
# 从基础配置开始，逐步添加功能
cp sslcat.conf.example sslcat.conf
# 然后手动添加需要的功能配置
```

## 配置合并策略

如果您需要多个功能，可以：

1. **从基础配置开始**，手动添加高级功能
2. **使用高级配置**，手动添加 Runner 功能
3. **创建自定义配置**，选择需要的功能模块

## 功能模块说明

### 基础功能模块
```json
{
  "server": { ... },
  "ssl": { ... },
  "admin": { ... },
  "proxy": { ... },
  "security": { ... }
}
```

### 高级功能模块
```json
{
  "cluster": { ... },
  "cdn_cache": { ... },
  "static_sites": [ ... ],
  "php_sites": [ ... ]
}
```

### Runner 功能模块
```json
{
  "runners": {
    "local": { ... },
    "docker": { ... },
    "git": { ... }
  }
}
```

## 配置文件命名规范

所有配置文件都遵循 `sslcat-{功能}.conf.example` 的命名规范：

- `sslcat.conf.example` - 基础配置
- `sslcat-advanced.conf.example` - 高级配置  
- `sslcat-runners.conf.example` - Runner 配置

## 使用建议

1. **开发环境**: 使用 `sslcat-runners.conf.example`
2. **生产环境**: 使用 `sslcat-advanced.conf.example`
3. **简单部署**: 使用 `sslcat.conf.example`

## 配置验证

启动 SSLcat 时会自动验证配置文件的完整性：

```bash
# 验证配置
sslcat --config sslcat.conf --validate

# 启动服务
sslcat --config sslcat.conf
```

## 配置迁移

如果您已有配置文件，可以：

1. **备份现有配置**
2. **选择新的配置模板**
3. **手动迁移设置**
4. **测试新配置**

```bash
# 备份现有配置
cp sslcat.conf sslcat.conf.backup

# 使用新模板
cp sslcat-runners.conf.example sslcat.conf

# 手动调整配置
vim sslcat.conf
```
