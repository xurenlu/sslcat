# Template Marketplace - Media Services Category

This document provides detailed information about all templates in the Media Services category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Video Services

### Jellyfin ✅ Tested and Passed

**Function**: Jellyfin is an open-source media server, similar to Plex, that can stream movies, TV shows, music, and other media content.

**Docker Image**: `jellyfin/jellyfin:latest`

**Configuration Options**:
- `JELLYFIN_VERSION`: Jellyfin version (default: latest, optional: 10.9, 10.8)
- `JELLYFIN_PORT`: Jellyfin web service port (default: 8096)

**Test Status**: ✅ Tested and Passed

**Description**: Jellyfin is one of the most popular open-source media servers with complete functionality, supporting various media formats such as video, music, images, etc. Requires mounting media directories.

**Setup URL**: `http://{{PRIMARY_DOMAIN}}/web/index.html`

---

### PeerTube ✅ Tested and Passed

**Function**: PeerTube decentralized video platform, supports video sharing and streaming.

**Docker Image**: `chocobozzz/peertube:latest`

**Configuration Options**:
- `PEERTUBE_VERSION`: PeerTube version (default: latest)
- `PEERTUBE_PORT`: PeerTube web service port (default: 9000)

**Test Status**: ✅ Tested and Passed

**Description**: PeerTube is a decentralized video platform that supports video sharing and streaming playback.

---

### Owncast ✅ Tested and Passed

**Function**: Owncast live streaming platform, self-hosted live streaming server.

**Docker Image**: `owncast/owncast:latest`

**Configuration Options**:
- `OWNCAST_VERSION`: Owncast version (default: latest)
- `OWNCAST_PORT`: Owncast web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Owncast is a self-hosted live streaming platform that can be used for game streaming, conference streaming, and other scenarios.

---

### Plex ⏳ Not Tested

**Function**: Plex media server, streams media content.

**Docker Image**: `plexinc/pms-docker:latest`

**Configuration Options**:
- `PLEX_VERSION`: Plex version (default: latest)
- `PLEX_PORT`: Plex web service port (default: 32400)

**Test Status**: ⏳ Not Tested

**Description**: Plex is one of the most popular media servers with powerful features, but requires Plex Pass to use advanced features.

---

### Emby ⏳ Not Tested

**Function**: Emby media server, streams media content.

**Docker Image**: `emby/embyserver:latest`

**Configuration Options**:
- `EMBY_VERSION`: Emby version (default: latest)
- `EMBY_PORT`: Emby web service port (default: 8096)

**Test Status**: ⏳ Not Tested

**Description**: Emby is a powerful media server that supports multiple clients and devices.

---

## Music Services

### Navidrome ⏳ Not Tested

**Function**: Navidrome music server, Subsonic-compatible music streaming server.

**Docker Image**: `deluan/navidrome:latest`

**Configuration Options**:
- `NAVIDROME_VERSION`: Navidrome version (default: latest)
- `NAVIDROME_PORT`: Navidrome web service port (default: 4533)

**Test Status**: ⏳ Not Tested

**Description**: Navidrome is a lightweight music server that supports Subsonic API with a beautiful interface.

---

### Airsonic ⏳ Not Tested

**Function**: Airsonic music server, Subsonic-compatible music streaming server.

**Docker Image**: `airsonic/airsonic:latest`

**Configuration Options**:
- `AIRSONIC_VERSION`: Airsonic version (default: latest)
- `AIRSONIC_PORT`: Airsonic web service port (default: 4040)

**Test Status**: ⏳ Not Tested

**Description**: Airsonic is a fully-featured music server that supports multiple audio formats and clients.

---

### Lidarr ✅ Tested and Passed

**Function**: Lidarr music management tool, automatically downloads and manages music.

**Docker Image**: `lscr.io/linuxserver/lidarr:latest`

**Configuration Options**:
- `LIDARR_VERSION`: Lidarr version (default: latest)
- `LIDARR_PORT`: Lidarr web service port (default: 8686)

**Test Status**: ✅ Tested and Passed

**Description**: Lidarr is the music version of Sonarr, can automatically download and manage music, supports multiple music sources.

---

### Radarr ⏳ Not Tested

**Function**: Radarr movie management tool, automatically downloads and manages movies.

**Docker Image**: `lscr.io/linuxserver/radarr:latest`

**Configuration Options**:
- `RADARR_VERSION`: Radarr version (default: latest)
- `RADARR_PORT`: Radarr web service port (default: 7878)

**Test Status**: ⏳ Not Tested

**Description**: Radarr is the movie version of Sonarr, can automatically download and manage movies.

---

### Readarr ⏳ Not Tested

**Function**: Readarr ebook management tool, automatically downloads and manages ebooks.

**Docker Image**: `lscr.io/linuxserver/readarr:latest`

**Configuration Options**:
- `READARR_VERSION`: Readarr version (default: latest)
- `READARR_PORT`: Readarr web service port (default: 8787)

**Test Status**: ⏳ Not Tested

**Description**: Readarr is the ebook version of Sonarr, can automatically download and manage ebooks.

---

### Sonarr ⏳ Not Tested

**Function**: Sonarr TV series management tool, automatically downloads and manages TV series.

**Docker Image**: `lscr.io/linuxserver/sonarr:latest`

**Configuration Options**:
- `SONARR_VERSION`: Sonarr version (default: latest)
- `SONARR_PORT`: Sonarr web service port (default: 8989)

**Test Status**: ⏳ Not Tested

**Description**: Sonarr is one of the most popular TV series management tools that can automatically download and manage TV series.

---

### Prowlarr ⏳ Not Tested

**Function**: Prowlarr index management tool, unified management of multiple index sources.

**Docker Image**: `lscr.io/linuxserver/prowlarr:latest`

**Configuration Options**:
- `PROWLARR_VERSION`: Prowlarr version (default: latest)
- `PROWLARR_PORT`: Prowlarr web service port (default: 9696)

**Test Status**: ⏳ Not Tested

**Description**: Prowlarr is an index management tool that can unify multiple index sources for use by Sonarr, Radarr, etc.

---

### Ombi ✅ Tested and Passed

**Function**: Ombi media request tool, users can request movies, TV series, etc.

**Docker Image**: `linuxserver/ombi:latest`

**Configuration Options**:
- `OMBI_VERSION`: Ombi version (default: latest)
- `OMBI_PORT`: Ombi web service port (default: 3579)

**Test Status**: ✅ Tested and Passed

**Description**: Ombi is a media request tool where users can request movies, TV series, etc., and administrators can approve and automatically download them.

---

## Image Services

### Immich ⏳ Not Tested

**Function**: Immich photo library, open-source alternative to Google Photos.

**Docker Image**: `immich/immich:latest`

**Configuration Options**:
- `IMMICH_VERSION`: Immich version (default: latest)
- `IMMICH_PORT`: Immich web service port (default: 2283)

**Test Status**: ⏳ Not Tested

**Description**: Immich is a fully-featured photo library that provides Google Photos-like functionality.

---

### PhotoPrism ✅ Tested and Passed

**Function**: PhotoPrism photo management tool, AI-driven photo organization and management.

**Docker Image**: `photoprism/photoprism:latest`

**Configuration Options**:
- `PHOTOPRISM_VERSION`: PhotoPrism version (default: latest)
- `PHOTOPRISM_PORT`: PhotoPrism web service port (default: 2342)

**Test Status**: ✅ Tested and Passed

**Description**: PhotoPrism is an AI-driven photo management tool that can automatically identify photo content, faces, locations, etc.

---

### Piwigo ✅ Tested and Passed

**Function**: Piwigo photo library, fully-featured photo management platform.

**Docker Image**: `linuxserver/piwigo:latest`

**Configuration Options**:
- `PIWIGO_VERSION`: Piwigo version (default: latest)
- `PIWIGO_PORT`: Piwigo web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: Piwigo is a fully-featured photo library that supports albums, tags, comments, and other features.

---

### Lychee ⏳ Not Tested

**Function**: Lychee photo library, simple and beautiful photo management tool.

**Docker Image**: `lychee/lychee:latest`

**Configuration Options**:
- `LYCHEE_VERSION`: Lychee version (default: latest)
- `LYCHEE_PORT`: Lychee web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Lychee is a simple and beautiful photo library with a friendly interface and complete functionality.

---

### Pixelfed ⏳ Not Tested

**Function**: Pixelfed image social platform, decentralized alternative to Instagram.

**Docker Image**: `pixelfed/pixelfed:latest`

**Configuration Options**:
- `PIXELFED_VERSION`: Pixelfed version (default: latest)
- `PIXELFED_PORT`: Pixelfed web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Pixelfed is a decentralized image social platform that supports the ActivityPub protocol.

---

## Other Media

### Komga ⏳ Not Tested

**Function**: Komga manga management tool, manages and reads manga.

**Docker Image**: `gotson/komga:latest`

**Configuration Options**:
- `KOMGA_VERSION`: Komga version (default: latest)
- `KOMGA_PORT`: Komga web service port (default: 25600)

**Test Status**: ⏳ Not Tested

**Description**: Komga is a manga management tool that can manage and read manga, supporting multiple formats.

---

### Calibre Web ✅ Tested and Passed

**Function**: Calibre Web ebook management tool, web interface based on Calibre.

**Docker Image**: `linuxserver/calibre-web:latest`

**Configuration Options**:
- `CALIBRE_WEB_VERSION`: Calibre Web version (default: latest)
- `CALIBRE_WEB_PORT`: Calibre Web service port (default: 8083)

**Test Status**: ✅ Tested and Passed

**Description**: Calibre Web is a web interface based on Calibre that can manage and read ebooks.

---

## Summary

The Media Services category contains **19 templates**, of which:
- ✅ **Tested and Passed**: 8 templates (Jellyfin, PeerTube, Owncast, Lidarr, Ombi, PhotoPrism, Piwigo, Calibre Web)
- ⏳ **Not Tested**: 11 templates (Plex, Emby, Navidrome, Airsonic, Radarr, Readarr, Sonarr, Prowlarr, Immich, Lychee, Pixelfed, Komga)

Tested templates are mainly concentrated in video services (Jellyfin, PeerTube, Owncast) and image services (PhotoPrism, Piwigo). Most music service templates have not completed testing.

---

*Last updated: 2025-11-11*
