# Template Marketplace - Collaboration Tools Category

This document provides detailed information about all templates in the Collaboration Tools category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Team Collaboration

### Mattermost ✅ Tested and Passed

**Function**: Open-source alternative to Slack, team collaboration and real-time chat platform, supports channels, private chats, file sharing, etc.

**Docker Image**: `mattermost/mattermost-team-edition:latest` (main service), `postgres:15` (database)

**Configuration Options**:
- `MATTERMOST_VERSION`: Mattermost version (default: latest, optional: 9.0, 8.1)
- `POSTGRES_VERSION`: PostgreSQL version (default: 15, optional: 16, 14)
- `MATTERMOST_PORT`: Mattermost web service port (default: 8065)

**Test Status**: ✅ Tested and Passed

**Description**: Mattermost is one of the most popular open-source alternatives to Slack, with complete functionality supporting channels, private chats, file sharing, integrations, etc.

**Access URL**: `http://{{PRIMARY_DOMAIN}}:8065`

**Default Account**: admin / admin

---

### Element ✅ Tested and Passed

**Function**: Element decentralized chat application, based on Matrix protocol.

**Docker Image**: `vectorim/element-web:latest`

**Configuration Options**:
- `ELEMENT_VERSION`: Element version (default: latest)
- `ELEMENT_PORT`: Element web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: Element is a decentralized chat application based on the Matrix protocol, supporting end-to-end encryption.

---

### Jitsi Meet ⏳ Not Tested

**Function**: Jitsi Meet video conferencing platform, open-source video conferencing solution.

**Docker Image**: `jitsi/web:latest`

**Configuration Options**:
- `JITSI_VERSION`: Jitsi Meet version (default: latest)
- `JITSI_PORT`: Jitsi Meet web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Jitsi Meet is an open-source video conferencing platform that supports multi-person video conferencing, screen sharing, etc.

---

### Rocket.Chat ⏳ Not Tested

**Function**: Rocket.Chat team collaboration platform, open-source alternative to Slack.

**Docker Image**: `rocketchat/rocket.chat:latest`

**Configuration Options**:
- `ROCKETCHAT_VERSION`: Rocket.Chat version (default: latest)
- `ROCKETCHAT_PORT`: Rocket.Chat web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Rocket.Chat is a fully-featured team collaboration platform that supports channels, private chats, video conferencing, etc.

---

## Document Collaboration

### BookStack ✅ Tested and Passed

**Function**: BookStack knowledge base platform, suitable for team document collaboration.

**Docker Image**: `linuxserver/bookstack:latest`

**Configuration Options**:
- `BOOKSTACK_VERSION`: BookStack version (default: latest)
- `BOOKSTACK_PORT`: BookStack web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: BookStack is a knowledge base platform that provides a hierarchical structure of books, chapters, and pages, suitable for team document collaboration.

---

### Wiki.js ✅ Tested and Passed

**Function**: Wiki.js modern wiki system, powerful knowledge base platform.

**Docker Image**: `ghcr.io/requarks/wiki:latest`

**Configuration Options**:
- `WIKIJS_VERSION`: Wiki.js version (default: latest)
- `WIKIJS_PORT`: Wiki.js web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Wiki.js is a modern wiki system that supports Markdown, visual editing, permission management, etc.

---

### HedgeDoc ✅ Tested and Passed

**Function**: HedgeDoc collaborative document editor, supports Markdown and real-time collaboration.

**Docker Image**: `quay.io/hedgedoc/hedgedoc:latest`

**Configuration Options**:
- `HEDGEDOC_VERSION`: HedgeDoc version (default: latest)
- `HEDGEDOC_PORT`: HedgeDoc web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: HedgeDoc is a collaborative document editor that supports Markdown, real-time collaboration, presentation mode, etc.

---

### Outline ✅ Tested and Passed

**Function**: Outline knowledge base platform, modern team knowledge management tool.

**Docker Image**: `outlinewiki/outline:latest`

**Configuration Options**:
- `OUTLINE_VERSION`: Outline version (default: latest)
- `OUTLINE_PORT`: Outline web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Outline is a modern knowledge base platform with a beautiful interface and complete functionality, suitable for team knowledge management.

---

## Online Office

### OnlyOffice ⏳ Not Tested

**Function**: OnlyOffice online office suite, supports document, spreadsheet, and presentation editing.

**Docker Image**: `onlyoffice/documentserver:latest`

**Configuration Options**:
- `ONLYOFFICE_VERSION`: OnlyOffice version (default: latest)
- `ONLYOFFICE_PORT`: OnlyOffice web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: OnlyOffice is a fully-featured online office suite that supports online editing of documents, spreadsheets, and presentations.

---

### Collabora Online ⏳ Not Tested

**Function**: Collabora Online online office suite, online version of LibreOffice.

**Docker Image**: `collabora/code:latest`

**Configuration Options**:
- `COLLABORA_VERSION`: Collabora Online version (default: latest)
- `COLLABORA_PORT`: Collabora Online web service port (default: 9980)

**Test Status**: ⏳ Not Tested

**Description**: Collabora Online is the online version of LibreOffice, supporting online editing of documents, spreadsheets, and presentations.

---

### Excalidraw ⏳ Not Tested

**Function**: Excalidraw online drawing tool, hand-drawn style diagram drawing.

**Docker Image**: `excalidraw/excalidraw:latest`

**Configuration Options**:
- `EXCALIDRAW_VERSION`: Excalidraw version (default: latest)
- `EXCALIDRAW_PORT`: Excalidraw web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Excalidraw is an online drawing tool that provides hand-drawn style diagram drawing functionality, suitable for drawing flowcharts, architecture diagrams, etc.

---

## Other Collaboration Tools

### Meeting Management System ⏳ Not Tested

**Function**: Meeting management system, manages meeting reservations and resources.

**Docker Image**: `meeting/management:latest`

**Configuration Options**:
- `MEETING_VERSION`: Meeting management system version (default: latest)
- `MEETING_PORT`: Meeting management system web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: Meeting management system provides meeting reservation, meeting room management, resource allocation, and other features.

---

### Home Assistant ✅ Tested and Passed

**Function**: Home Assistant smart home platform, unified management of smart devices.

**Docker Image**: `homeassistant/home-assistant:latest`

**Configuration Options**:
- `HOMEASSISTANT_VERSION`: Home Assistant version (default: latest)
- `HOMEASSISTANT_PORT`: Home Assistant web service port (default: 8123)

**Test Status**: ✅ Tested and Passed

**Description**: Home Assistant is the most popular open-source smart home platform, supporting multiple smart device protocols and integrations.

---

### Domoticz ✅ Tested and Passed

**Function**: Domoticz smart home platform, lightweight smart home control system.

**Docker Image**: `domoticz/domoticz:latest`

**Configuration Options**:
- `DOMOTICZ_VERSION`: Domoticz version (default: latest)
- `DOMOTICZ_PORT`: Domoticz web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Domoticz is a lightweight smart home control system that supports multiple smart device protocols.

---

### Tandoor Recipes ⏳ Not Tested

**Function**: Tandoor Recipes recipe management application, supports importing, sharing, and managing recipes.

**Docker Image**: `vabene1111/recipes:latest`

**Configuration Options**:
- `TANDOOR_VERSION`: Tandoor Recipes version (default: latest, optional: 1.6, 1.5)
- `TANDOOR_PORT`: Tandoor Recipes web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: Tandoor Recipes is an open-source recipe management application that supports importing, sharing, and managing recipes.

---

### ntfy ⏳ Not Tested

**Function**: ntfy push notification service, simple push notification server.

**Docker Image**: `binwiederhier/ntfy:latest`

**Configuration Options**:
- `NTFY_VERSION`: ntfy version (default: latest)
- `NTFY_PORT`: ntfy web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: ntfy is a simple push notification server that can send push notifications via HTTP.

---

## Summary

The Collaboration Tools category contains **14 templates**, of which:
- ✅ **Tested and Passed**: 8 templates (Mattermost, Element, BookStack, Wiki.js, HedgeDoc, Outline, Home Assistant, Domoticz)
- ⏳ **Not Tested**: 6 templates (Jitsi Meet, Rocket.Chat, OnlyOffice, Collabora Online, Excalidraw, Meeting Management System, Tandoor Recipes, ntfy)

Tested templates are mainly concentrated in team collaboration (Mattermost, Element) and document collaboration (BookStack, Wiki.js, HedgeDoc, Outline). Online office templates (OnlyOffice, Collabora Online) have not completed testing.

---

*Last updated: 2025-11-11*
