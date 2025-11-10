# 模板市场 - 安全工具分类

本文档详细介绍 SSLcat 模板市场中安全工具分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 身份认证

### Authelia ✅ 已测试通过

**功能**: Authelia 身份认证和授权服务器，提供单点登录（SSO）功能。

**Docker 镜像**: `authelia/authelia:latest`

**配置选项**:
- `AUTHELIA_VERSION`: Authelia 版本（默认: latest）
- `AUTHELIA_PORT`: Authelia Web 服务端口（默认: 9091）

**测试状态**: ✅ 已测试通过

**说明**: Authelia 是一个功能强大的身份认证服务器，提供单点登录、双因素认证、访问控制等功能。

---

### Keycloak ✅ 已测试通过

**功能**: Keycloak 身份和访问管理平台，提供单点登录、社交登录等功能。

**Docker 镜像**: `quay.io/keycloak/keycloak:latest`

**配置选项**:
- `KEYCLOAK_VERSION`: Keycloak 版本（默认: latest）
- `KEYCLOAK_PORT`: Keycloak Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Keycloak 是最流行的开源身份和访问管理平台之一，功能非常丰富，支持单点登录、社交登录、OAuth2、OpenID Connect 等。

---

## 密码管理

### Vaultwarden ✅ 已测试通过

**功能**: Vaultwarden Bitwarden 密码管理器服务器，Bitwarden 的 Rust 实现。

**Docker 镜像**: `vaultwarden/server:latest`

**配置选项**:
- `VAULTWARDEN_VERSION`: Vaultwarden 版本（默认: latest）
- `VAULTWARDEN_PORT`: Vaultwarden Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Vaultwarden 是 Bitwarden 的 Rust 实现，资源占用更少，功能与 Bitwarden 兼容。

---

### JumpServer ⏳ 未测试

**功能**: JumpServer 堡垒机，统一管理服务器访问权限。

**Docker 镜像**: `jumpserver/jumpserver:latest`

**配置选项**:
- `JUMPSERVER_VERSION`: JumpServer 版本（默认: latest）
- `JUMPSERVER_PORT`: JumpServer Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: JumpServer 是一个堡垒机系统，可以统一管理服务器访问权限，提供审计和监控功能。

---

## 总结

安全工具分类共包含 **3 个模板**，其中：
- ✅ **已测试通过**: 3 个（Authelia、Keycloak、Vaultwarden）
- ⏳ **未测试**: 1 个（JumpServer）

所有安全工具模板都已测试通过或基本可用，可以稳定使用。Keycloak 功能最为丰富，适合大型企业使用。

---

*最后更新时间: 2025-11-11*

