# SSLcat Template Market Guide

## Overview

The SSLcat Template Market is a powerful application deployment platform offering **362+** enterprise-grade application templates, covering all scenarios from AI applications to enterprise tools, from databases to media services. Through the Template Market, you can deploy various applications with one click, without manually configuring Docker Compose, domains, SSL certificates, and other complex settings.

## Core Features

### 🚀 One-Click Deployment
- **Zero-Configuration Deployment**: Select a template, fill in necessary parameters, and deploy with one click
- **Automatic Domain Configuration**: Automatically configure domains and subdomains
- **Automatic SSL Certificates**: Automatically request and configure Let's Encrypt SSL certificates
- **Automatic Health Checks**: Built-in health check mechanism ensures services run normally

### 📦 Rich Template Library
- **362+ Templates**: Covering 21 main categories and 130+ subcategories
- **137 Tested and Verified**: All templates have been verified through automated testing
- **Continuous Updates**: Regularly add new templates and optimize existing ones

### 🔧 Flexible Configuration
- **Version Selection**: Support for selecting application versions
- **Port Configuration**: Custom port mapping
- **Environment Variables**: Flexible environment variable configuration
- **Resource Limits**: CPU, memory, and GPU resource configuration

### 🔐 Secure and Reliable
- **Automatic Credential Generation**: Automatically generate secure database passwords and API tokens
- **Data Persistence**: Automatically configure data volumes to ensure data security
- **Access Control**: Role-based access control

## Template Categories

### AI Applications (76)

#### Large Language Model Chat (8)
- **Ollama** - Local LLM runtime environment
- **Open WebUI** - AI chat interface
- **LibreChat** - ChatGPT alternative
- **Chatbot UI** - AI chat interface
- **ChatGLM** - Chinese LLM
- **Baichuan** - Baichuan LLM
- **Qwen** - Qwen LLM
- **Yi** - Yi LLM

#### Image Generation (8)
- **Stable Diffusion WebUI** - Powerful AI image generation tool
- **ComfyUI** - Node-based AI workflow
- **Replicate Stable Diffusion** - Stable Diffusion on Replicate
- **Replicate SDXL** - SDXL model
- **Replicate ControlNet** - ControlNet model
- **DALL-E Mini** - DALL-E Mini image generation
- **Midjourney Alternative** - Midjourney alternative
- **Waifu Diffusion** - Anime-style image generation

#### Code Generation (4)
- **CodeGeeX** - AI code generation
- **Codeium** - AI code assistant
- **Tabby** - AI code completion
- **Continue** - AI code editor

#### Voice/Video Generation (4)
- **Pika** - AI video generation
- **RunwayML** - AI video editing
- **Stable Video Diffusion** - Video generation model
- **Replicate Stable Video** - Replicate video generation

#### OCR/Text Recognition (3)
- **EasyOCR** - Multi-language OCR
- **PaddleOCR** - Chinese OCR
- **TrOCR** - Transformer OCR (⚠️ Image not available)

#### TTS/Voice Synthesis (3)
- **Coqui TTS** - Text-to-speech
- **Piper TTS** - Lightweight TTS
- **Bark** - Text-to-audio generation

#### Other AI Tools
- **AnythingLLM** - Private ChatGPT
- **LocalAI** - OpenAI-compatible API
- **LangChain** - AI application framework
- **LlamaIndex** - RAG framework
- **Text Generation WebUI** - Local LLM interface
- **TorchServe** - PyTorch model serving
- **Replicate Proxy** - Replicate model proxy
- And more...

### Enterprise Tools (156)

#### HR/Personnel Management (13)
- Attendance Management System
- Clock-in System
- Work Hours Management System
- Payroll Management System
- Employee Directory
- Dormitory Management System
- Shuttle Management System
- Shift Scheduling System
- Training Management System
- **Moodle** - Online learning platform
- **Open edX** - Online learning platform
- Knowledge Exam System
- **Kimai** - Time tracking

#### Project Management (11)
- Project Portfolio Management (PPM)
- Project Cost Management System
- Resource Management System
- Project Risk Management System
- **Leantime** - Project management tool
- **Plane** - Project management platform
- **Taiga** - Agile project management
- **Vikunja** - Task management
- **Kanboard** - Kanban management
- **OpenProject** - Project management
- **Linear Alternative** - Linear alternative

#### ERP/Supply Chain (7)
- Small ERP System
- Inventory Management System
- Warehouse Management System
- Supplier Management System
- Supplier Self-Service Platform
- Procurement Portal
- Contract Management System

#### Document Management (6)
- Document Version Control System
- Seal Management System
- Archive Management System
- Document Compliance System
- **Paperless-ngx** - Paperless document management
- **Mayan EDMS** - Enterprise document management system

#### Compliance & Audit (4)
- Compliance Management System
- Audit Management System
- Risk Management System
- Document Compliance System

#### Collaboration Tools (6)
- Meeting Management System
- **Mattermost** - Team collaboration platform
- **Element** - Decentralized chat
- **Jitsi Meet** - Video conferencing
- **Excalidraw** - Online drawing
- **OnlyOffice** - Online office suite

### Databases (21)

#### Relational Databases
- **MySQL** - Most popular relational database
- **PostgreSQL** - Powerful open-source database
- **MariaDB** - MySQL fork
- **TimescaleDB** - Time-series database

#### NoSQL Databases
- **MongoDB** - Document database
- **Redis** - In-memory database
- **Cassandra** - Distributed database
- **CouchDB** - Document database
- **ClickHouse** - Analytical database
- **InfluxDB** - Time-series database

#### Vector Databases (5)
- **Milvus** - Vector database
- **Qdrant** - Vector search engine
- **Weaviate** - Vector database
- **Chroma** - Vector database
- **Pinecone Alternative** - Pinecone alternative

#### Database Management Tools
- **phpMyAdmin** - MySQL management
- **Adminer** - Database management
- **pgAdmin** - PostgreSQL management
- **mongo-express** - MongoDB management

### Media Services (19)

#### Video Services
- **Jellyfin** - Media server
- **Plex** - Media server
- **Emby** - Media server
- **Owncast** - Live streaming platform
- **PeerTube** - Video platform

#### Music Services
- **Airsonic** - Music server
- **Navidrome** - Music server
- **Lidarr** - Music management
- **Radarr** - Movie management
- **Readarr** - E-book management
- **Sonarr** - TV series management
- **Prowlarr** - Index management

#### Image Services
- **Immich** - Photo library
- **PhotoPrism** - Photo management
- **Lychee** - Photo album
- **Piwigo** - Photo library
- **Pixelfed** - Image social network

#### Others
- **Komga** - Comic management
- **Calibre Web** - E-book management

### DevOps (12)

#### CI/CD Tools
- **Jenkins** - Continuous integration
- **Drone** - CI/CD platform
- **GitHub Actions Runner** - GitHub Actions Runner
- **Woodpecker CI** - CI/CD platform

#### Monitoring Tools
- **Grafana** - Monitoring dashboard
- **Prometheus** - Monitoring system
- **Netdata** - Real-time monitoring
- **Glances** - System monitoring
- **Uptime Kuma** - Website monitoring

#### Log Management
- **Graylog** - Log management
- **Loki** - Log aggregation
- **Seq** - Structured logging

#### Others
- **Portainer** - Container management
- **Dozzle** - Docker log viewer

### CMS (12)

- **WordPress** - Most popular CMS
- **Ghost** - Blogging platform
- **Strapi** - Headless CMS
- **Drupal** - Enterprise CMS
- **Wagtail** - Django CMS
- **Hexo** - Static blog
- **Hugo** - Static site generator
- **Nuxt.js** - Vue.js framework
- **Gatsby** - React static site
- **Docusaurus** - Documentation site
- **Plume** - Blogging platform
- **Keystone** - Node.js CMS

### Other Categories

#### Analytics Tools (10)
- **Matomo** - Web analytics
- **Umami** - Website analytics
- **PostHog** - Product analytics
- **Metabase** - Business intelligence
- **Plausible** - Privacy-friendly analytics
- **Fathom** - Website analytics
- **GoatCounter** - Website statistics
- **Ackee** - Website analytics
- **Countly** - Product analytics
- **Redash** - SQL queries and visualization

#### CRM (5)
- **SuiteCRM** - CRM system
- **EspoCRM** - CRM system
- **Dolibarr** - ERP/CRM
- **Odoo** - ERP/CRM
- **ERPNext** - ERP system

#### Customer Support (4)
- **Chatwoot** - Customer support system
- **Zammad** - Customer support platform
- **FreeScout** - Customer support system
- **osTicket** - Ticket system

#### E-commerce Platforms (4)
- **WooCommerce** - WordPress e-commerce plugin
- **Magento** - E-commerce platform
- **OpenCart** - E-commerce system
- **PrestaShop** - E-commerce platform
- **Shopware** - E-commerce platform

#### Security Tools (3)
- **Authelia** - Authentication
- **Keycloak** - Identity and access management
- **Vaultwarden** - Password manager
- **JumpServer** - Bastion host

#### RSS Readers (5)
- **FreshRSS** - RSS reader
- **Tiny Tiny RSS** - RSS reader
- **Miniflux** - RSS reader
- **Stringer** - RSS reader
- **Selfoss** - RSS reader

#### Forum Platforms (5)
- **Discourse** - Forum platform
- **Flarum** - Forum platform
- **NodeBB** - Forum platform
- **Talkyard** - Forum platform
- **Answer** - Q&A platform

## Usage

### Web UI Usage

1. **Access Template Market**
   - Log in to SSLcat admin panel
   - Navigate to "Template Market" page

2. **Browse Templates**
   - Use category filter: AI, Database, DevOps, etc.
   - Use tag filter: gpu, web, api, etc.
   - Use keyword search: Enter application name or feature

3. **View Template Details**
   - Click template card to view detailed information
   - View template description, configuration options, resource requirements
   - Check if GPU support is required

4. **Deploy Template**
   - Click "Deploy" button
   - Fill in necessary configuration parameters:
     - Application name
     - Domain (optional, auto-generated)
     - Version selection
     - Port configuration
     - Environment variables
   - Confirm deployment

5. **View Deployment Status**
   - Check deployment status in "Application List"
   - View deployment logs
   - Wait for deployment to complete

### API Usage

#### Get Template List

```bash
# Get all templates
GET /api/git-server/templates

# Filter by category
GET /api/git-server/templates?category=ai

# Filter by tag
GET /api/git-server/templates?tag=gpu

# Keyword search
GET /api/git-server/templates?keyword=wordpress

# Show all templates (including untested)
GET /api/git-server/templates?showAll=true
```

#### Get Template Details

```bash
GET /api/git-server/templates/{template_id}
```

Response example:
```json
{
  "meta": {
    "id": "wordpress",
    "name": "WordPress",
    "category": "cms",
    "description": "Most popular content management system",
    "variables": [
      {
        "name": "WORDPRESS_VERSION",
        "type": "select",
        "default": "latest",
        "options": ["latest", "6.4", "6.3"]
      }
    ],
    "services": [...],
    "gpu_required": false
  },
  "readme": "# WordPress\n\n...",
  "assets": []
}
```

#### Deploy Template

```bash
POST /api/git-server/templates/deploy
Content-Type: application/json

{
  "name": "my-wordpress",
  "template_id": "wordpress",
  "domain": "blog.example.com",
  "domains": ["blog.example.com", "www.blog.example.com"],
  "auto_ssl": true,
  "parameters": {
    "WORDPRESS_VERSION": "latest",
    "WORDPRESS_PORT": "8080"
  }
}
```

## Template Status

### Tested and Verified (137)
These templates have been verified through automated testing and are stable to use. The API returns only these templates by default.

### Untested (225+)
These templates have not completed testing yet and may have configuration issues. They can be viewed using the `?showAll=true` parameter.

### Unavailable (4)
Docker images for these templates do not exist or are inaccessible:
- **manga-translator** - Image not available
- **speech-translator** - Image not available
- **whisperx** - Image not available
- **trocr** - Image not available

## GPU Template Usage

Some AI templates require GPU support. Before deployment, ensure:

1. **Server Configuration**
   - Install NVIDIA drivers
   - Install NVIDIA Container Toolkit
   - Configure Docker to use NVIDIA runtime

2. **Template Identification**
   - Template details will show `gpu_required: true`
   - Template cards will display GPU tag

3. **Deployment Notes**
   - GPU templates take longer to start (may need to download models)
   - Sufficient VRAM required (recommended 8GB+)
   - Some templates may require GitHub Container Registry Token

## GitHub Container Registry Support

Some templates use `ghcr.io` images and require GitHub Personal Access Token configuration:

1. **Create Token**
   - Visit GitHub Settings > Developer settings > Personal access tokens
   - Create Token with `read:packages` permission

2. **Configure Token**
   - Set `GITHUB_TOKEN` environment variable in SSLcat configuration
   - Or provide Token during deployment

## Best Practices

### 1. Choose the Right Template
- Prioritize tested and verified templates
- Select appropriate version based on needs
- Pay attention to GPU and resource requirements

### 2. Configuration Recommendations
- Use meaningful application names
- Configure custom domains (recommended)
- Enable automatic SSL certificates
- Set reasonable resource limits

### 3. Data Management
- Regularly backup data volumes
- Use persistent storage
- Pay attention to data migration

### 4. Security Recommendations
- Use strong passwords (auto-generated)
- Regularly update application versions
- Configure firewall rules
- Enable access control

## FAQ

### Q: How to view detailed template configuration?
A: Click the template card or use the API to get template details, check the `variables` field to understand all configuration options.

### Q: What to do if template deployment fails?
A: Check deployment logs. Common issues:
- Port conflicts: Modify port configuration
- Insufficient resources: Increase server resources
- Image pull failures: Check network and authentication

### Q: How to update deployed applications?
A: You can update applications by modifying the Docker Compose file or redeploying.

### Q: Do templates support custom configuration?
A: Yes, each template supports configuration through `variables`, including version, ports, environment variables, etc.

### Q: How to contribute new templates?
A: Refer to template development documentation, create `template.yaml` and `docker-compose.yml` files, and submit a Pull Request.

## Related Documentation

- [Template Library Statistics](../templates/template-library-statistics.md)
- [Template Test Status](../testing/template-test-status.md)
- [Docker Compose Template Implementation](../development/docker-compose-template-implementation.md)
- [Template Expansion Plan](../development/template-expansion-plan.md)

## Summary

The SSLcat Template Market provides **362+** enterprise-grade application templates, covering all scenarios from AI applications to enterprise tools. With one-click deployment, automatic configuration, and secure and reliable features, application deployment becomes simple and efficient.

Whether you are a developer, DevOps engineer, or enterprise user, you can find suitable applications in the Template Market and quickly set up your own services.

---

*Last updated: 2025-11-11*

