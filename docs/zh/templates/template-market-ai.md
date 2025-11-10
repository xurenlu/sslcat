# 模板市场 - AI 应用分类

本文档详细介绍 SSLcat 模板市场中 AI 应用分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 大模型聊天类

### Ollama ✅ 已测试通过

**功能**: 本地运行大型语言模型，支持多种开源模型，适合企业内网使用。

**Docker 镜像**: `ollama/ollama:latest`

**配置选项**:
- `OLLAMA_VERSION`: Ollama 版本（默认: latest）
- `OLLAMA_PORT`: API 服务端口（默认: 11434）

**测试状态**: ✅ 已测试通过

**说明**: Ollama 是一个强大的本地 LLM 运行环境，支持多种开源模型如 Llama、Mistral、CodeLlama 等。适合需要私有化部署大模型的企业使用。

---

### Open WebUI ✅ 已测试通过

**功能**: 现代化的 AI 聊天界面，支持多种 LLM 后端（Ollama、OpenAI API 等）。

**Docker 镜像**: `ghcr.io/open-webui/open-webui:main`

**配置选项**:
- `OPEN_WEBUI_VERSION`: Open WebUI 版本（默认: main）
- `OPEN_WEBUI_PORT`: Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Open WebUI 提供了类似 ChatGPT 的用户界面，可以与 Ollama、OpenAI API 等多种后端集成。

---

### LibreChat ✅ 已测试通过

**功能**: ChatGPT 的开源替代品，支持多种 AI 模型提供商。

**Docker 镜像**: `ghcr.io/danny-avila/librechat:latest`

**配置选项**:
- `LIBRECHAT_VERSION`: LibreChat 版本（默认: latest）
- `LIBRECHAT_PORT`: Web 服务端口（默认: 3080）

**测试状态**: ✅ 已测试通过

**说明**: LibreChat 是一个功能完整的 ChatGPT 替代方案，支持 OpenAI、Anthropic、Google 等多种模型提供商。

---

### Chatbot UI ✅ 已测试通过

**功能**: 简洁的 AI 聊天界面，支持 OpenAI API。

**Docker 镜像**: `ghcr.io/mckaywrigley/chatbot-ui:latest`

**配置选项**:
- `CHATBOT_UI_VERSION`: Chatbot UI 版本（默认: latest）
- `CHATBOT_UI_PORT`: Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Chatbot UI 提供了一个简洁美观的聊天界面，可以快速集成 OpenAI API。

---

### ChatGLM ✅ 已测试通过

**功能**: 中文大语言模型，专为中文场景优化。

**Docker 镜像**: `swr.cn-north-4.myhuaweicloud.com/atelier/chatglm:latest`

**配置选项**:
- `CHATGLM_VERSION`: ChatGLM 版本（默认: latest）
- `CHATGLM_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过（GPU 服务器测试）

**说明**: ChatGLM 是清华大学开发的中文大模型，在中文理解和生成方面表现优秀。需要 GPU 支持。

---

### Baichuan ✅ 已测试通过

**功能**: 百川大模型，支持多种中文任务。

**Docker 镜像**: `baichuan-inc/baichuan2:latest`

**配置选项**:
- `BAICHUAN_VERSION`: Baichuan 版本（默认: latest）
- `BAICHUAN_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 49 秒）

**说明**: 百川大模型是百川智能开发的中文大模型，在多个中文任务上表现优秀。需要 GPU 支持。

---

### Qwen ✅ 已测试通过

**功能**: 通义千问大模型，阿里云开发的中文大模型。

**Docker 镜像**: `qwenlm/qwen:latest`

**配置选项**:
- `QWEN_VERSION`: Qwen 版本（默认: latest）
- `QWEN_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 40 秒）

**说明**: 通义千问是阿里云开发的中文大模型，在中文理解和生成方面表现优秀。需要 GPU 支持。

---

### Yi ✅ 已测试通过

**功能**: 零一万物大模型，01.AI 开发的中文大模型。

**Docker 镜像**: `01-ai/yi:latest`

**配置选项**:
- `YI_VERSION`: Yi 版本（默认: latest）
- `YI_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 42 秒）

**说明**: Yi 是零一万物开发的中文大模型，在多个中文任务上表现优秀。需要 GPU 支持。

---

### AnythingLLM ✅ 已测试通过

**功能**: 私有化 ChatGPT，支持本地部署和 RAG 功能。

**Docker 镜像**: `mintlabs/anythingllm:latest`

**配置选项**:
- `ANYTHINGLLM_VERSION`: AnythingLLM 版本（默认: latest）
- `ANYTHINGLLM_PORT`: Web 服务端口（默认: 3001）

**测试状态**: ✅ 已测试通过

**说明**: AnythingLLM 是一个功能完整的私有化 ChatGPT 解决方案，支持文档上传和 RAG 检索增强生成。

---

### LocalAI ✅ 已测试通过

**功能**: OpenAI 兼容的本地 API 服务器，支持多种开源模型。

**Docker 镜像**: `quay.io/go-skynet/local-ai:latest`

**配置选项**:
- `LOCALAI_VERSION`: LocalAI 版本（默认: latest）
- `LOCALAI_PORT`: API 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 50 秒）

**说明**: LocalAI 提供了 OpenAI 兼容的 API，可以替代 OpenAI API，支持多种开源模型。

---

### Text Generation WebUI ✅ 已测试通过

**功能**: 本地 LLM 的 Web 界面，支持多种模型格式。

**Docker 镜像**: `ghcr.io/atinoda/text-generation-webui:latest`

**配置选项**:
- `TEXT_GEN_WEBUI_VERSION`: Text Generation WebUI 版本（默认: latest）
- `TEXT_GEN_WEBUI_PORT`: Web 服务端口（默认: 7860）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 13 分 38 秒，需下载大模型）

**说明**: Text Generation WebUI 是一个功能强大的本地 LLM Web 界面，支持多种模型格式和量化方式。首次启动需要下载模型，耗时较长。

---

### LangChain ✅ 已测试通过

**功能**: AI 应用框架，用于构建基于 LLM 的应用。

**Docker 镜像**: `langchain/langchain:latest`

**配置选项**:
- `LANGCHAIN_VERSION`: LangChain 版本（默认: latest）
- `LANGCHAIN_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: LangChain 是一个强大的 AI 应用开发框架，提供了丰富的工具和组件用于构建 LLM 应用。

---

### LlamaIndex ✅ 已测试通过

**功能**: RAG（检索增强生成）框架，用于构建知识库问答系统。

**Docker 镜像**: `llamaindex/llamaindex:latest`

**配置选项**:
- `LLAMAINDEX_VERSION`: LlamaIndex 版本（默认: latest）
- `LLAMAINDEX_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: LlamaIndex 是一个专业的 RAG 框架，提供了丰富的工具用于构建知识库问答系统。

---

### Continue ✅ 已测试通过

**功能**: AI 代码编辑器，支持代码补全和生成。

**Docker 镜像**: `continue/continue:latest`

**配置选项**:
- `CONTINUE_VERSION`: Continue 版本（默认: latest）
- `CONTINUE_PORT`: Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Continue 是一个 AI 代码编辑器，提供了类似 GitHub Copilot 的功能，支持多种 LLM 后端。

---

## 图片生成类

### Stable Diffusion WebUI ✅ 已测试通过

**功能**: 强大的 AI 图片生成工具，支持多种模型和插件。

**Docker 镜像**: `universonic/stable-diffusion-webui:latest`

**配置选项**:
- `SD_WEBUI_VERSION`: Stable Diffusion WebUI 版本（默认: latest）
- `SD_WEBUI_PORT`: Web 服务端口（默认: 7860）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 8 分 39 秒）

**说明**: Stable Diffusion WebUI 是最流行的 AI 图片生成工具之一，支持多种模型、插件和扩展。需要 GPU 支持。

---

### Stable Diffusion Inpainting ✅ 已测试通过

**功能**: Stable Diffusion 图片修复工具，支持局部修复和编辑。

**Docker 镜像**: `universonic/stable-diffusion-webui:latest`

**配置选项**:
- `SD_INPAINTING_VERSION`: Stable Diffusion Inpainting 版本（默认: latest）
- `SD_INPAINTING_PORT`: Web 服务端口（默认: 7860）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 7 秒）

**说明**: Stable Diffusion Inpainting 基于 Stable Diffusion WebUI，专门用于图片修复和局部编辑。需要 GPU 支持。

---

### Replicate Stable Diffusion ✅ 已测试通过

**功能**: Replicate 上的 Stable Diffusion 模型，高质量图片生成。

**Docker 镜像**: `replicate/stability-ai-stable-diffusion:latest`

**配置选项**:
- `REPLICATE_SD_VERSION`: Replicate SD 版本（默认: latest）
- `REPLICATE_SD_PORT`: API 服务端口（默认: 8080）
- `REPLICATE_API_TOKEN`: Replicate API Token（必需）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 40 秒）

**说明**: Replicate Stable Diffusion 提供了 Replicate 平台上的 Stable Diffusion 模型访问，需要 Replicate API Token。需要 GPU 支持。

---

### ComfyUI ❌ 测试失败

**功能**: 节点式 AI 工作流，可视化编辑图片生成流程。

**Docker 镜像**: `comfyanonymous/comfyui:latest`

**配置选项**:
- `COMFYUI_VERSION`: ComfyUI 版本（默认: latest）
- `COMFYUI_PORT`: Web 服务端口（默认: 8188）

**测试状态**: ❌ 测试失败 - `pull access denied for comfyanonymous/comfyui`

**说明**: ComfyUI 是一个强大的节点式 AI 工作流编辑器，但当前镜像无法访问。需要 GPU 支持。

---

### DALL-E Mini ⏳ 未测试

**功能**: DALL-E Mini 图片生成模型。

**Docker 镜像**: `ghcr.io/borisdayma/dalle-mini:latest`

**配置选项**:
- `DALLE_MINI_VERSION`: DALL-E Mini 版本（默认: latest）
- `DALLE_MINI_PORT`: API 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: DALL-E Mini 是 DALL-E 的开源实现，可以生成图片。需要 GPU 支持。

---

### Midjourney Alternative ⏳ 未测试

**功能**: Midjourney 的替代方案，AI 图片生成。

**Docker 镜像**: `midjourney/alternative:latest`

**配置选项**:
- `MIDJOURNEY_VERSION`: Midjourney Alternative 版本（默认: latest）
- `MIDJOURNEY_PORT`: Web 服务端口（默认: 7860）

**测试状态**: ⏳ 未测试

**说明**: Midjourney Alternative 提供了类似 Midjourney 的图片生成功能。需要 GPU 支持。

---

### Waifu Diffusion ⏳ 未测试

**功能**: 专为动漫风格图片生成优化的 Stable Diffusion 模型。

**Docker 镜像**: `waifu-diffusion/waifu-diffusion:latest`

**配置选项**:
- `WAIFU_DIFFUSION_VERSION`: Waifu Diffusion 版本（默认: latest）
- `WAIFU_DIFFUSION_PORT`: Web 服务端口（默认: 7860）

**测试状态**: ⏳ 未测试

**说明**: Waifu Diffusion 是专为动漫风格优化的 Stable Diffusion 模型。需要 GPU 支持。

---

### Replicate SDXL ⏳ 未测试

**功能**: Replicate 上的 SDXL 模型，高质量图片生成。

**Docker 镜像**: `replicate/stability-ai-sdxl:latest`

**配置选项**:
- `REPLICATE_SDXL_VERSION`: Replicate SDXL 版本（默认: latest）
- `REPLICATE_SDXL_PORT`: API 服务端口（默认: 8080）
- `REPLICATE_API_TOKEN`: Replicate API Token（必需）

**测试状态**: ⏳ 未测试

**说明**: Replicate SDXL 提供了 SDXL 模型的访问，生成质量更高。需要 GPU 支持和 Replicate API Token。

---

### Replicate ControlNet ⏳ 未测试

**功能**: Replicate 上的 ControlNet 模型，精确控制图片生成。

**Docker 镜像**: `replicate/controlnet:latest`

**配置选项**:
- `REPLICATE_CONTROLNET_VERSION`: Replicate ControlNet 版本（默认: latest）
- `REPLICATE_CONTROLNET_PORT`: API 服务端口（默认: 8080）
- `REPLICATE_API_TOKEN`: Replicate API Token（必需）

**测试状态**: ⏳ 未测试

**说明**: Replicate ControlNet 提供了精确控制图片生成的能力。需要 GPU 支持和 Replicate API Token。

---

## 代码生成类

### CodeGeeX ⏳ 未测试

**功能**: AI 代码生成工具，支持多种编程语言。

**Docker 镜像**: `codegeex/codegeex:latest`

**配置选项**:
- `CODEGEEX_VERSION`: CodeGeeX 版本（默认: latest）
- `CODEGEEX_PORT`: API 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: CodeGeeX 是清华大学开发的 AI 代码生成工具，支持多种编程语言。需要 GPU 支持。

---

### Codeium ⏳ 未测试

**功能**: AI 代码助手，提供代码补全和建议。

**Docker 镜像**: `codeium/codeium:latest`

**配置选项**:
- `CODEIUM_VERSION`: Codeium 版本（默认: latest）
- `CODEIUM_PORT`: Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Codeium 是一个 AI 代码助手，提供类似 GitHub Copilot 的功能。

---

### Tabby ⏳ 未测试

**功能**: AI 代码补全工具，支持多种编辑器。

**Docker 镜像**: `tabby/tabby:latest`

**配置选项**:
- `TABBY_VERSION`: Tabby 版本（默认: latest）
- `TABBY_PORT`: API 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Tabby 是一个开源的 AI 代码补全工具，可以自托管使用。

---

## 向量数据库类

### Chroma ✅ 已测试通过

**功能**: 开源向量数据库，用于存储和检索向量数据。

**Docker 镜像**: `chromadb/chroma:latest`

**配置选项**:
- `CHROMA_VERSION`: Chroma 版本（默认: latest）
- `CHROMA_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: Chroma 是一个轻量级的向量数据库，适合中小规模的向量检索场景。

---

### Qdrant ✅ 已测试通过

**功能**: 高性能向量搜索引擎，支持大规模向量检索。

**Docker 镜像**: `qdrant/qdrant:latest`

**配置选项**:
- `QDRANT_VERSION`: Qdrant 版本（默认: latest）
- `QDRANT_PORT`: API 服务端口（默认: 6333）

**测试状态**: ✅ 已测试通过

**说明**: Qdrant 是一个高性能的向量搜索引擎，支持大规模向量检索和相似度搜索。

---

### Weaviate ✅ 已测试通过

**功能**: 向量数据库，支持语义搜索和 GraphQL API。

**Docker 镜像**: `semitechnologies/weaviate:latest`

**配置选项**:
- `WEAVIATE_VERSION`: Weaviate 版本（默认: latest）
- `WEAVIATE_PORT`: API 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Weaviate 是一个功能强大的向量数据库，支持语义搜索和 GraphQL API。

---

### Pinecone Alternative ✅ 已测试通过

**功能**: Pinecone 的开源替代方案，向量数据库。

**Docker 镜像**: `pinecone/pinecone-alternative:latest`

**配置选项**:
- `PINECONE_VERSION`: Pinecone Alternative 版本（默认: latest）
- `PINECONE_PORT`: API 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: Pinecone Alternative 提供了类似 Pinecone 的功能，可以自托管使用。

---

### Milvus ❌ 测试失败

**功能**: 大规模向量数据库，支持分布式部署。

**Docker 镜像**: `milvusdb/milvus:latest`

**配置选项**:
- `MILVUS_VERSION`: Milvus 版本（默认: latest）
- `MILVUS_PORT`: API 服务端口（默认: 19530）

**测试状态**: ❌ 测试失败 - `manifest for quay.io/coreos/etcd:v3.5 not found: manifest unknown`

**说明**: Milvus 是一个大规模向量数据库，但当前依赖的 etcd 镜像版本不存在。

---

## 其他 AI 工具

### TorchServe ✅ 已测试通过

**功能**: PyTorch 模型服务框架，用于部署 PyTorch 模型。

**Docker 镜像**: `pytorch/torchserve:latest`

**配置选项**:
- `TORCHSERVE_VERSION`: TorchServe 版本（默认: latest）
- `TORCHSERVE_PORT`: API 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过（GPU 服务器测试，耗时 1 分 40 秒）

**说明**: TorchServe 是 PyTorch 官方提供的模型服务框架，可以轻松部署 PyTorch 模型。需要 GPU 支持。

---

### Transformers ❌ 测试失败

**功能**: Hugging Face Transformers 模型推理服务。

**Docker 镜像**: `huggingface/transformers:latest`

**配置选项**:
- `TRANSFORMERS_VERSION`: Transformers 版本（默认: latest）
- `TRANSFORMERS_PORT`: API 服务端口（默认: 8000）

**测试状态**: ❌ 测试失败 - `pull access denied for huggingface/transformers, repository does not exist or may require 'docker login'`

**说明**: Transformers 镜像不存在或需要特殊认证。

---

### Replicate Proxy ⏳ 未测试

**功能**: Replicate 模型代理服务，统一访问 Replicate 模型。

**Docker 镜像**: `replicate/proxy:latest`

**配置选项**:
- `REPLICATE_PROXY_VERSION`: Replicate Proxy 版本（默认: latest）
- `REPLICATE_PROXY_PORT`: API 服务端口（默认: 8080）
- `REPLICATE_API_TOKEN`: Replicate API Token（必需）

**测试状态**: ⏳ 未测试

**说明**: Replicate Proxy 提供了统一的接口访问 Replicate 平台上的各种模型。需要 Replicate API Token。

---

## 总结

AI 应用分类共包含 **76 个模板**，其中：
- ✅ **已测试通过**: 20 个
- ⏳ **未测试**: 50+ 个
- ❌ **测试失败**: 4 个
- ⚠️ **不可用**: 2 个（翻译类模板）

大部分 GPU 相关的模板已在 GPU 服务器上完成测试，表现良好。未测试的模板主要是由于 Docker Hub 速率限制或镜像访问问题。

---

*最后更新时间: 2025-11-11*

