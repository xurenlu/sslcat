# 模板市场 - 媒体服务分类

本文档详细介绍 SSLcat 模板市场中媒体服务分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 视频服务

### Jellyfin ✅ 已测试通过

**功能**: Jellyfin 是一个开源的媒体服务器，类似 Plex，可以流式传输电影、电视节目、音乐等媒体内容。

**Docker 镜像**: `jellyfin/jellyfin:latest`

**配置选项**:
- `JELLYFIN_VERSION`: Jellyfin 版本（默认: latest，可选: 10.9, 10.8）
- `JELLYFIN_PORT`: Jellyfin Web 服务端口（默认: 8096）

**测试状态**: ✅ 已测试通过

**说明**: Jellyfin 是最流行的开源媒体服务器之一，功能完整，支持视频、音乐、图片等多种媒体格式。需要挂载媒体目录。

**设置地址**: `http://{{PRIMARY_DOMAIN}}/web/index.html`

---

### PeerTube ✅ 已测试通过

**功能**: PeerTube 去中心化视频平台，支持视频分享和流媒体。

**Docker 镜像**: `chocobozzz/peertube:latest`

**配置选项**:
- `PEERTUBE_VERSION`: PeerTube 版本（默认: latest）
- `PEERTUBE_PORT`: PeerTube Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: PeerTube 是一个去中心化的视频平台，支持视频分享和流媒体播放。

---

### Owncast ✅ 已测试通过

**功能**: Owncast 直播平台，自托管直播服务器。

**Docker 镜像**: `owncast/owncast:latest`

**配置选项**:
- `OWNCAST_VERSION`: Owncast 版本（默认: latest）
- `OWNCAST_PORT`: Owncast Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Owncast 是一个自托管的直播平台，可以用于游戏直播、会议直播等场景。

---

### Plex ⏳ 未测试

**功能**: Plex 媒体服务器，流式传输媒体内容。

**Docker 镜像**: `plexinc/pms-docker:latest`

**配置选项**:
- `PLEX_VERSION`: Plex 版本（默认: latest）
- `PLEX_PORT`: Plex Web 服务端口（默认: 32400）

**测试状态**: ⏳ 未测试

**说明**: Plex 是最流行的媒体服务器之一，功能强大，但需要 Plex Pass 才能使用高级功能。

---

### Emby ⏳ 未测试

**功能**: Emby 媒体服务器，流式传输媒体内容。

**Docker 镜像**: `emby/embyserver:latest`

**配置选项**:
- `EMBY_VERSION`: Emby 版本（默认: latest）
- `EMBY_PORT`: Emby Web 服务端口（默认: 8096）

**测试状态**: ⏳ 未测试

**说明**: Emby 是一个功能强大的媒体服务器，支持多种客户端和设备。

---

## 音乐服务

### Navidrome ⏳ 未测试

**功能**: Navidrome 音乐服务器，Subsonic 兼容的音乐流媒体服务器。

**Docker 镜像**: `deluan/navidrome:latest`

**配置选项**:
- `NAVIDROME_VERSION`: Navidrome 版本（默认: latest）
- `NAVIDROME_PORT`: Navidrome Web 服务端口（默认: 4533）

**测试状态**: ⏳ 未测试

**说明**: Navidrome 是一个轻量级的音乐服务器，支持 Subsonic API，界面美观。

---

### Airsonic ⏳ 未测试

**功能**: Airsonic 音乐服务器，Subsonic 兼容的音乐流媒体服务器。

**Docker 镜像**: `airsonic/airsonic:latest`

**配置选项**:
- `AIRSONIC_VERSION`: Airsonic 版本（默认: latest）
- `AIRSONIC_PORT`: Airsonic Web 服务端口（默认: 4040）

**测试状态**: ⏳ 未测试

**说明**: Airsonic 是一个功能完整的音乐服务器，支持多种音频格式和客户端。

---

### Lidarr ✅ 已测试通过

**功能**: Lidarr 音乐管理工具，自动下载和管理音乐。

**Docker 镜像**: `lscr.io/linuxserver/lidarr:latest`

**配置选项**:
- `LIDARR_VERSION`: Lidarr 版本（默认: latest）
- `LIDARR_PORT`: Lidarr Web 服务端口（默认: 8686）

**测试状态**: ✅ 已测试通过

**说明**: Lidarr 是音乐版的 Sonarr，可以自动下载和管理音乐，支持多种音乐源。

---

### Radarr ⏳ 未测试

**功能**: Radarr 电影管理工具，自动下载和管理电影。

**Docker 镜像**: `lscr.io/linuxserver/radarr:latest`

**配置选项**:
- `RADARR_VERSION`: Radarr 版本（默认: latest）
- `RADARR_PORT`: Radarr Web 服务端口（默认: 7878）

**测试状态**: ⏳ 未测试

**说明**: Radarr 是电影版的 Sonarr，可以自动下载和管理电影。

---

### Readarr ⏳ 未测试

**功能**: Readarr 电子书管理工具，自动下载和管理电子书。

**Docker 镜像**: `lscr.io/linuxserver/readarr:latest`

**配置选项**:
- `READARR_VERSION`: Readarr 版本（默认: latest）
- `READARR_PORT`: Readarr Web 服务端口（默认: 8787）

**测试状态**: ⏳ 未测试

**说明**: Readarr 是电子书版的 Sonarr，可以自动下载和管理电子书。

---

### Sonarr ⏳ 未测试

**功能**: Sonarr 电视剧管理工具，自动下载和管理电视剧。

**Docker 镜像**: `lscr.io/linuxserver/sonarr:latest`

**配置选项**:
- `SONARR_VERSION`: Sonarr 版本（默认: latest）
- `SONARR_PORT`: Sonarr Web 服务端口（默认: 8989）

**测试状态**: ⏳ 未测试

**说明**: Sonarr 是最流行的电视剧管理工具之一，可以自动下载和管理电视剧。

---

### Prowlarr ⏳ 未测试

**功能**: Prowlarr 索引管理工具，统一管理多个索引源。

**Docker 镜像**: `lscr.io/linuxserver/prowlarr:latest`

**配置选项**:
- `PROWLARR_VERSION`: Prowlarr 版本（默认: latest）
- `PROWLARR_PORT`: Prowlarr Web 服务端口（默认: 9696）

**测试状态**: ⏳ 未测试

**说明**: Prowlarr 是一个索引管理工具，可以统一管理多个索引源，供 Sonarr、Radarr 等使用。

---

### Ombi ✅ 已测试通过

**功能**: Ombi 媒体请求工具，用户可以请求电影、电视剧等。

**Docker 镜像**: `linuxserver/ombi:latest`

**配置选项**:
- `OMBI_VERSION`: Ombi 版本（默认: latest）
- `OMBI_PORT`: Ombi Web 服务端口（默认: 3579）

**测试状态**: ✅ 已测试通过

**说明**: Ombi 是一个媒体请求工具，用户可以请求电影、电视剧等，管理员可以审批并自动下载。

---

## 图片服务

### Immich ⏳ 未测试

**功能**: Immich 照片库，Google Photos 的开源替代方案。

**Docker 镜像**: `immich/immich:latest`

**配置选项**:
- `IMMICH_VERSION`: Immich 版本（默认: latest）
- `IMMICH_PORT`: Immich Web 服务端口（默认: 2283）

**测试状态**: ⏳ 未测试

**说明**: Immich 是一个功能完整的照片库，提供类似 Google Photos 的功能。

---

### PhotoPrism ✅ 已测试通过

**功能**: PhotoPrism 照片管理工具，AI 驱动的照片组织和管理。

**Docker 镜像**: `photoprism/photoprism:latest`

**配置选项**:
- `PHOTOPRISM_VERSION`: PhotoPrism 版本（默认: latest）
- `PHOTOPRISM_PORT`: PhotoPrism Web 服务端口（默认: 2342）

**测试状态**: ✅ 已测试通过

**说明**: PhotoPrism 是一个 AI 驱动的照片管理工具，可以自动识别照片内容、人脸、地点等。

---

### Piwigo ✅ 已测试通过

**功能**: Piwigo 照片库，功能完整的照片管理平台。

**Docker 镜像**: `linuxserver/piwigo:latest`

**配置选项**:
- `PIWIGO_VERSION`: Piwigo 版本（默认: latest）
- `PIWIGO_PORT`: Piwigo Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Piwigo 是一个功能完整的照片库，支持相册、标签、评论等功能。

---

### Lychee ⏳ 未测试

**功能**: Lychee 照片库，简洁美观的照片管理工具。

**Docker 镜像**: `lychee/lychee:latest`

**配置选项**:
- `LYCHEE_VERSION`: Lychee 版本（默认: latest）
- `LYCHEE_PORT`: Lychee Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Lychee 是一个简洁美观的照片库，界面友好，功能完整。

---

### Pixelfed ⏳ 未测试

**功能**: Pixelfed 图片社交平台，去中心化的 Instagram 替代方案。

**Docker 镜像**: `pixelfed/pixelfed:latest`

**配置选项**:
- `PIXELFED_VERSION`: Pixelfed 版本（默认: latest）
- `PIXELFED_PORT`: Pixelfed Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Pixelfed 是一个去中心化的图片社交平台，支持 ActivityPub 协议。

---

## 其他媒体

### Komga ⏳ 未测试

**功能**: Komga 漫画管理工具，管理和阅读漫画。

**Docker 镜像**: `gotson/komga:latest`

**配置选项**:
- `KOMGA_VERSION`: Komga 版本（默认: latest）
- `KOMGA_PORT`: Komga Web 服务端口（默认: 25600）

**测试状态**: ⏳ 未测试

**说明**: Komga 是一个漫画管理工具，可以管理和阅读漫画，支持多种格式。

---

### Calibre Web ✅ 已测试通过

**功能**: Calibre Web 电子书管理工具，基于 Calibre 的 Web 界面。

**Docker 镜像**: `linuxserver/calibre-web:latest`

**配置选项**:
- `CALIBRE_WEB_VERSION`: Calibre Web 版本（默认: latest）
- `CALIBRE_WEB_PORT`: Calibre Web 服务端口（默认: 8083）

**测试状态**: ✅ 已测试通过

**说明**: Calibre Web 是基于 Calibre 的 Web 界面，可以管理和阅读电子书。

---

## 总结

媒体服务分类共包含 **19 个模板**，其中：
- ✅ **已测试通过**: 6 个（Jellyfin、PeerTube、Owncast、Lidarr、Ombi、PhotoPrism、Piwigo、Calibre Web）
- ⏳ **未测试**: 11 个（Plex、Emby、Navidrome、Airsonic、Radarr、Readarr、Sonarr、Prowlarr、Immich、Lychee、Pixelfed、Komga）

已测试通过的模板主要集中在视频服务（Jellyfin、PeerTube、Owncast）和图片服务（PhotoPrism、Piwigo）。音乐服务类模板大部分尚未完成测试。

---

*最后更新时间: 2025-11-11*

