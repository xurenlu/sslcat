# GPU 和 GUI 支持说明

## GPU 支持

### 配置要求

对于需要 GPU 的 AI 应用（如 Stable Diffusion、ComfyUI、LocalAI 等），Docker Compose 配置中已包含 GPU 支持：

```yaml
runtime: nvidia
environment:
  NVIDIA_VISIBLE_DEVICES: all
  NVIDIA_DRIVER_CAPABILITIES: compute,utility
```

### 系统要求

1. **NVIDIA GPU**：需要 NVIDIA GPU 硬件
2. **NVIDIA Driver**：需要安装 NVIDIA 驱动
3. **NVIDIA Container Toolkit**：需要安装 `nvidia-container-toolkit`

### 安装 NVIDIA Container Toolkit

#### Ubuntu/Debian
```bash
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list

sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker
```

#### CentOS/RHEL
```bash
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.repo | sudo tee /etc/yum.repos.d/nvidia-docker.repo

sudo yum install -y nvidia-container-toolkit
sudo systemctl restart docker
```

### 验证 GPU 支持

```bash
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi
```

## GUI 支持

### 当前状态

目前 Docker Compose 模板主要针对 Web 应用，通过浏览器访问，**不需要 X11/GUI 转发**。

### 如果需要 GUI 支持

如果某些应用需要 GUI 支持（如桌面应用），可以添加以下配置：

```yaml
services:
  app:
    environment:
      DISPLAY: ${DISPLAY}
    volumes:
      - /tmp/.X11-unix:/tmp/.X11-unix:rw
    network_mode: host
```

### X11 Forwarding 设置

1. **允许 X11 连接**：
```bash
xhost +local:docker
```

2. **在 Docker Compose 中添加**：
```yaml
environment:
  DISPLAY: ${DISPLAY}
volumes:
  - /tmp/.X11-unix:/tmp/.X11-unix:rw
```

### 注意事项

- 大多数 AI 应用（Stable Diffusion WebUI、ComfyUI 等）都提供 Web 界面，不需要 GUI 支持
- 如果需要运行桌面应用，建议使用 VNC 或 NoVNC 方案
- GPU 支持是必需的，GUI 支持是可选的

## 模板中的 GPU 配置

以下模板已配置 GPU 支持：

- `stable-diffusion-webui` - 需要 GPU
- `comfyui` - 需要 GPU
- `localai` - 可选 GPU
- `coqui-tts` - 可选 GPU
- `bark` - 需要 GPU
- `whisper` - 可选 GPU
- `ollama` - 可选 GPU

## 故障排查

### GPU 不可用

1. 检查 NVIDIA 驱动：
```bash
nvidia-smi
```

2. 检查 Docker GPU 支持：
```bash
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi
```

3. 检查容器日志：
```bash
docker-compose logs app-name
```

### GUI 不可用

1. 检查 DISPLAY 环境变量：
```bash
echo $DISPLAY
```

2. 检查 X11 权限：
```bash
xhost
```

3. 使用 VNC 替代方案（推荐）

