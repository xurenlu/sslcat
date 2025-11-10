# Template Marketplace - Customer Support Systems Category

This document provides detailed information about all templates in the Customer Support Systems category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Customer Support Systems

### Chatwoot ✅ Tested and Passed

**Function**: Chatwoot customer support system, modern multi-channel customer support platform.

**Docker Image**: `chatwoot/chatwoot:latest`

**Configuration Options**:
- `CHATWOOT_VERSION`: Chatwoot version (default: latest)
- `CHATWOOT_PORT`: Chatwoot web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Chatwoot is a modern customer support system that supports multiple channels (website, Facebook, Twitter, WhatsApp, etc.) with a beautiful interface and complete functionality.

---

### Zammad ⏳ Not Tested

**Function**: Zammad customer support platform, powerful customer support and ticket system.

**Docker Image**: `zammad/zammad:latest`

**Configuration Options**:
- `ZAMMAD_VERSION`: Zammad version (default: latest)
- `ZAMMAD_PORT`: Zammad web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Zammad is a powerful customer support platform that supports multiple channels, ticket management, knowledge base, etc.

---

### FreeScout ⏳ Not Tested

**Function**: FreeScout customer support system, open-source alternative to Help Scout.

**Docker Image**: `freescout/freescout:latest`

**Configuration Options**:
- `FREESCOUT_VERSION`: FreeScout version (default: latest)
- `FREESCOUT_PORT`: FreeScout web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: FreeScout is an open-source alternative to Help Scout, providing similar customer support functionality.

---

### osTicket ⏳ Not Tested

**Function**: osTicket ticket system, open-source ticket management platform.

**Docker Image**: `osticket/osticket:latest`

**Configuration Options**:
- `OSTICKET_VERSION`: osTicket version (default: latest)
- `OSTICKET_PORT`: osTicket web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: osTicket is an open-source ticket system suitable for small and medium enterprises.

---

## Summary

The Customer Support Systems category contains **4 templates**, of which:
- ✅ **Tested and Passed**: 1 template (Chatwoot)
- ⏳ **Not Tested**: 3 templates (Zammad, FreeScout, osTicket)

Chatwoot has been tested and passed, and can be used stably. Other customer support system templates have not completed testing.

---

*Last updated: 2025-11-11*
