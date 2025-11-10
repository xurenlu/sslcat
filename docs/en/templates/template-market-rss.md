# Template Marketplace - RSS Readers Category

This document provides detailed information about all templates in the RSS Readers category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## RSS Readers

### FreshRSS ✅ Tested and Passed

**Function**: FreshRSS RSS reader, powerful RSS aggregation and reading tool.

**Docker Image**: `linuxserver/freshrss:latest`

**Configuration Options**:
- `FRESHRSS_VERSION`: FreshRSS version (default: latest)
- `FRESHRSS_PORT`: FreshRSS web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: FreshRSS is a powerful RSS reader that supports multi-user, tags, filtering, and other features.

---

### Tiny Tiny RSS ⏳ Not Tested

**Function**: Tiny Tiny RSS RSS reader, fully-featured RSS aggregation tool.

**Docker Image**: `linuxserver/tt-rss:latest`

**Configuration Options**:
- `TTRSS_VERSION`: Tiny Tiny RSS version (default: latest)
- `TTRSS_PORT`: Tiny Tiny RSS web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Tiny Tiny RSS is a fully-featured RSS reader that supports multi-user, plugins, API, etc.

---

### Miniflux ⏳ Not Tested

**Function**: Miniflux RSS reader, minimalist RSS reader.

**Docker Image**: `miniflux/miniflux:latest`

**Configuration Options**:
- `MINIFLUX_VERSION`: Miniflux version (default: latest)
- `MINIFLUX_PORT`: Miniflux web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: Miniflux is a minimalist RSS reader with a clean interface and excellent performance.

---

### Stringer ⏳ Not Tested

**Function**: Stringer RSS reader, self-hosted RSS reader.

**Docker Image**: `stringer/stringer:latest`

**Configuration Options**:
- `STRINGER_VERSION`: Stringer version (default: latest)
- `STRINGER_PORT`: Stringer web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: Stringer is a self-hosted RSS reader with simple functionality and easy to use.

---

### Selfoss ⏳ Not Tested

**Function**: Selfoss RSS reader, multi-source RSS aggregation tool.

**Docker Image**: `selfoss/selfoss:latest`

**Configuration Options**:
- `SELFOSS_VERSION`: Selfoss version (default: latest)
- `SELFOSS_PORT`: Selfoss web service port (default: 8888)

**Test Status**: ⏳ Not Tested

**Description**: Selfoss is a multi-source RSS aggregation tool that supports RSS, Twitter, Facebook, and other sources.

---

## Summary

The RSS Readers category contains **5 templates**, of which:
- ✅ **Tested and Passed**: 1 template (FreshRSS)
- ⏳ **Not Tested**: 4 templates (Tiny Tiny RSS, Miniflux, Stringer, Selfoss)

FreshRSS has been tested and passed, and can be used stably. Other RSS reader templates have not completed testing.

---

*Last updated: 2025-11-11*
