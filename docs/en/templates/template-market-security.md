# Template Marketplace - Security Tools Category

This document provides detailed information about all templates in the Security Tools category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Identity Authentication

### Authelia ✅ Tested and Passed

**Function**: Authelia identity authentication and authorization server, provides single sign-on (SSO) functionality.

**Docker Image**: `authelia/authelia:latest`

**Configuration Options**:
- `AUTHELIA_VERSION`: Authelia version (default: latest)
- `AUTHELIA_PORT`: Authelia web service port (default: 9091)

**Test Status**: ✅ Tested and Passed

**Description**: Authelia is a powerful identity authentication server that provides single sign-on, two-factor authentication, access control, etc.

---

### Keycloak ✅ Tested and Passed

**Function**: Keycloak identity and access management platform, provides single sign-on, social login, etc.

**Docker Image**: `quay.io/keycloak/keycloak:latest`

**Configuration Options**:
- `KEYCLOAK_VERSION`: Keycloak version (default: latest)
- `KEYCLOAK_PORT`: Keycloak web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Keycloak is one of the most popular open-source identity and access management platforms with very rich features, supporting single sign-on, social login, OAuth2, OpenID Connect, etc.

---

## Password Management

### Vaultwarden ✅ Tested and Passed

**Function**: Vaultwarden Bitwarden password manager server, Rust implementation of Bitwarden.

**Docker Image**: `vaultwarden/server:latest`

**Configuration Options**:
- `VAULTWARDEN_VERSION`: Vaultwarden version (default: latest)
- `VAULTWARDEN_PORT`: Vaultwarden web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: Vaultwarden is a Rust implementation of Bitwarden with lower resource usage and Bitwarden-compatible functionality.

---

### JumpServer ⏳ Not Tested

**Function**: JumpServer bastion host, unified management of server access permissions.

**Docker Image**: `jumpserver/jumpserver:latest`

**Configuration Options**:
- `JUMPSERVER_VERSION`: JumpServer version (default: latest)
- `JUMPSERVER_PORT`: JumpServer web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: JumpServer is a bastion host system that can unify server access permissions and provide auditing and monitoring functionality.

---

## Summary

The Security Tools category contains **4 templates**, of which:
- ✅ **Tested and Passed**: 3 templates (Authelia, Keycloak, Vaultwarden)
- ⏳ **Not Tested**: 1 template (JumpServer)

All security tool templates have been tested and passed or are basically available, and can be used stably. Keycloak has the most features and is suitable for large enterprises.

---

*Last updated: 2025-11-11*
