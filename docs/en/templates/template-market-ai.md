# Template Marketplace - AI Applications Category

This document provides detailed information about all templates in the AI Applications category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Large Language Model Chat

### Ollama ✅ Tested and Passed

**Function**: Run large language models locally, supports multiple open-source models, suitable for enterprise intranet use.

**Docker Image**: `ollama/ollama:latest`

**Configuration Options**:
- `OLLAMA_VERSION`: Ollama version (default: latest)
- `OLLAMA_PORT`: API service port (default: 11434)

**Test Status**: ✅ Tested and Passed

**Description**: Ollama is a powerful local LLM runtime environment that supports various open-source models such as Llama, Mistral, CodeLlama, etc. Suitable for enterprises that need private deployment of large models.

---

### Open WebUI ✅ Tested and Passed

**Function**: Modern AI chat interface, supports multiple LLM backends (Ollama, OpenAI API, etc.).

**Docker Image**: `ghcr.io/open-webui/open-webui:main`

**Configuration Options**:
- `OPEN_WEBUI_VERSION`: Open WebUI version (default: main)
- `OPEN_WEBUI_PORT`: Web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Open WebUI provides a ChatGPT-like user interface that can integrate with various backends such as Ollama, OpenAI API, etc.

---

### LibreChat ✅ Tested and Passed

**Function**: Open-source alternative to ChatGPT, supports multiple AI model providers.

**Docker Image**: `ghcr.io/danny-avila/librechat:latest`

**Configuration Options**:
- `LIBRECHAT_VERSION`: LibreChat version (default: latest)
- `LIBRECHAT_PORT`: Web service port (default: 3080)

**Test Status**: ✅ Tested and Passed

**Description**: LibreChat is a fully-featured ChatGPT alternative that supports multiple model providers such as OpenAI, Anthropic, Google, etc.

---

### Chatbot UI ✅ Tested and Passed

**Function**: Simple AI chat interface, supports OpenAI API.

**Docker Image**: `ghcr.io/mckaywrigley/chatbot-ui:latest`

**Configuration Options**:
- `CHATBOT_UI_VERSION`: Chatbot UI version (default: latest)
- `CHATBOT_UI_PORT`: Web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Chatbot UI provides a clean and beautiful chat interface that can quickly integrate with OpenAI API.

---

### ChatGLM ✅ Tested and Passed

**Function**: Chinese large language model, optimized for Chinese scenarios.

**Docker Image**: `swr.cn-north-4.myhuaweicloud.com/atelier/chatglm:latest`

**Configuration Options**:
- `CHATGLM_VERSION`: ChatGLM version (default: latest)
- `CHATGLM_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed (GPU server tested)

**Description**: ChatGLM is a Chinese large model developed by Tsinghua University, excellent in Chinese understanding and generation. Requires GPU support.

---

### Baichuan ✅ Tested and Passed

**Function**: Baichuan large model, supports multiple Chinese tasks.

**Docker Image**: `baichuan-inc/baichuan2:latest`

**Configuration Options**:
- `BAICHUAN_VERSION`: Baichuan version (default: latest)
- `BAICHUAN_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 49 seconds)

**Description**: Baichuan is a Chinese large model developed by Baichuan Intelligence, excellent in multiple Chinese tasks. Requires GPU support.

---

### Qwen ✅ Tested and Passed

**Function**: Qwen large model, Chinese large model developed by Alibaba Cloud.

**Docker Image**: `qwenlm/qwen:latest`

**Configuration Options**:
- `QWEN_VERSION`: Qwen version (default: latest)
- `QWEN_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 40 seconds)

**Description**: Qwen is a Chinese large model developed by Alibaba Cloud, excellent in Chinese understanding and generation. Requires GPU support.

---

### Yi ✅ Tested and Passed

**Function**: Yi large model, Chinese large model developed by 01.AI.

**Docker Image**: `01-ai/yi:latest`

**Configuration Options**:
- `YI_VERSION`: Yi version (default: latest)
- `YI_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 42 seconds)

**Description**: Yi is a Chinese large model developed by 01.AI, excellent in multiple Chinese tasks. Requires GPU support.

---

### AnythingLLM ✅ Tested and Passed

**Function**: Private ChatGPT, supports local deployment and RAG functionality.

**Docker Image**: `mintlabs/anythingllm:latest`

**Configuration Options**:
- `ANYTHINGLLM_VERSION`: AnythingLLM version (default: latest)
- `ANYTHINGLLM_PORT`: Web service port (default: 3001)

**Test Status**: ✅ Tested and Passed

**Description**: AnythingLLM is a fully-featured private ChatGPT solution that supports document upload and RAG retrieval-augmented generation.

---

### LocalAI ✅ Tested and Passed

**Function**: OpenAI-compatible local API server, supports multiple open-source models.

**Docker Image**: `quay.io/go-skynet/local-ai:latest`

**Configuration Options**:
- `LOCALAI_VERSION`: LocalAI version (default: latest)
- `LOCALAI_PORT`: API service port (default: 8080)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 50 seconds)

**Description**: LocalAI provides OpenAI-compatible APIs that can replace OpenAI API, supporting multiple open-source models.

---

### Text Generation WebUI ✅ Tested and Passed

**Function**: Web interface for local LLMs, supports multiple model formats.

**Docker Image**: `ghcr.io/atinoda/text-generation-webui:latest`

**Configuration Options**:
- `TEXT_GEN_WEBUI_VERSION`: Text Generation WebUI version (default: latest)
- `TEXT_GEN_WEBUI_PORT`: Web service port (default: 7860)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 13 minutes 38 seconds, requires downloading large models)

**Description**: Text Generation WebUI is a powerful web interface for local LLMs, supporting multiple model formats and quantization methods. First startup requires downloading models, which takes longer.

---

### LangChain ✅ Tested and Passed

**Function**: AI application framework for building LLM-based applications.

**Docker Image**: `langchain/langchain:latest`

**Configuration Options**:
- `LANGCHAIN_VERSION`: LangChain version (default: latest)
- `LANGCHAIN_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: LangChain is a powerful AI application development framework that provides rich tools and components for building LLM applications.

---

### LlamaIndex ✅ Tested and Passed

**Function**: RAG (Retrieval-Augmented Generation) framework for building knowledge base Q&A systems.

**Docker Image**: `llamaindex/llamaindex:latest`

**Configuration Options**:
- `LLAMAINDEX_VERSION`: LlamaIndex version (default: latest)
- `LLAMAINDEX_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: LlamaIndex is a professional RAG framework that provides rich tools for building knowledge base Q&A systems.

---

### Continue ✅ Tested and Passed

**Function**: AI code editor, supports code completion and generation.

**Docker Image**: `continue/continue:latest`

**Configuration Options**:
- `CONTINUE_VERSION`: Continue version (default: latest)
- `CONTINUE_PORT`: Web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Continue is an AI code editor that provides GitHub Copilot-like functionality, supporting multiple LLM backends.

---

## Image Generation

### Stable Diffusion WebUI ✅ Tested and Passed

**Function**: Powerful AI image generation tool, supports multiple models and plugins.

**Docker Image**: `universonic/stable-diffusion-webui:latest`

**Configuration Options**:
- `SD_WEBUI_VERSION`: Stable Diffusion WebUI version (default: latest)
- `SD_WEBUI_PORT`: Web service port (default: 7860)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 8 minutes 39 seconds)

**Description**: Stable Diffusion WebUI is one of the most popular AI image generation tools, supporting multiple models, plugins, and extensions. Requires GPU support.

---

### Stable Diffusion Inpainting ✅ Tested and Passed

**Function**: Stable Diffusion image inpainting tool, supports local repair and editing.

**Docker Image**: `universonic/stable-diffusion-webui:latest`

**Configuration Options**:
- `SD_INPAINTING_VERSION`: Stable Diffusion Inpainting version (default: latest)
- `SD_INPAINTING_PORT`: Web service port (default: 7860)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 7 seconds)

**Description**: Stable Diffusion Inpainting is based on Stable Diffusion WebUI, specifically designed for image inpainting and local editing. Requires GPU support.

---

### Replicate Stable Diffusion ✅ Tested and Passed

**Function**: Stable Diffusion model on Replicate platform, high-quality image generation.

**Docker Image**: `replicate/stability-ai-stable-diffusion:latest`

**Configuration Options**:
- `REPLICATE_SD_VERSION`: Replicate SD version (default: latest)
- `REPLICATE_SD_PORT`: API service port (default: 8080)
- `REPLICATE_API_TOKEN`: Replicate API Token (required)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 40 seconds)

**Description**: Replicate Stable Diffusion provides access to Stable Diffusion models on the Replicate platform, requires Replicate API Token. Requires GPU support.

---

### ComfyUI ❌ Test Failed

**Function**: Node-based AI workflow, visual editing of image generation processes.

**Docker Image**: `comfyanonymous/comfyui:latest`

**Configuration Options**:
- `COMFYUI_VERSION`: ComfyUI version (default: latest)
- `COMFYUI_PORT`: Web service port (default: 8188)

**Test Status**: ❌ Test Failed - `pull access denied for comfyanonymous/comfyui`

**Description**: ComfyUI is a powerful node-based AI workflow editor, but the current image cannot be accessed. Requires GPU support.

---

### DALL-E Mini ⏳ Not Tested

**Function**: DALL-E Mini image generation model.

**Docker Image**: `ghcr.io/borisdayma/dalle-mini:latest`

**Configuration Options**:
- `DALLE_MINI_VERSION`: DALL-E Mini version (default: latest)
- `DALLE_MINI_PORT`: API service port (default: 8000)

**Test Status**: ⏳ Not Tested

**Description**: DALL-E Mini is an open-source implementation of DALL-E that can generate images. Requires GPU support.

---

### Midjourney Alternative ⏳ Not Tested

**Function**: Alternative to Midjourney, AI image generation.

**Docker Image**: `midjourney/alternative:latest`

**Configuration Options**:
- `MIDJOURNEY_VERSION`: Midjourney Alternative version (default: latest)
- `MIDJOURNEY_PORT`: Web service port (default: 7860)

**Test Status**: ⏳ Not Tested

**Description**: Midjourney Alternative provides Midjourney-like image generation functionality. Requires GPU support.

---

### Waifu Diffusion ⏳ Not Tested

**Function**: Stable Diffusion model optimized for anime-style image generation.

**Docker Image**: `waifu-diffusion/waifu-diffusion:latest`

**Configuration Options**:
- `WAIFU_DIFFUSION_VERSION`: Waifu Diffusion version (default: latest)
- `WAIFU_DIFFUSION_PORT`: Web service port (default: 7860)

**Test Status**: ⏳ Not Tested

**Description**: Waifu Diffusion is a Stable Diffusion model optimized for anime style. Requires GPU support.

---

### Replicate SDXL ⏳ Not Tested

**Function**: SDXL model on Replicate platform, high-quality image generation.

**Docker Image**: `replicate/stability-ai-sdxl:latest`

**Configuration Options**:
- `REPLICATE_SDXL_VERSION`: Replicate SDXL version (default: latest)
- `REPLICATE_SDXL_PORT`: API service port (default: 8080)
- `REPLICATE_API_TOKEN`: Replicate API Token (required)

**Test Status**: ⏳ Not Tested

**Description**: Replicate SDXL provides access to SDXL models, with higher generation quality. Requires GPU support and Replicate API Token.

---

### Replicate ControlNet ⏳ Not Tested

**Function**: ControlNet model on Replicate platform, precise control of image generation.

**Docker Image**: `replicate/controlnet:latest`

**Configuration Options**:
- `REPLICATE_CONTROLNET_VERSION`: Replicate ControlNet version (default: latest)
- `REPLICATE_CONTROLNET_PORT`: API service port (default: 8080)
- `REPLICATE_API_TOKEN`: Replicate API Token (required)

**Test Status**: ⏳ Not Tested

**Description**: Replicate ControlNet provides precise control over image generation. Requires GPU support and Replicate API Token.

---

## Code Generation

### CodeGeeX ⏳ Not Tested

**Function**: AI code generation tool, supports multiple programming languages.

**Docker Image**: `codegeex/codegeex:latest`

**Configuration Options**:
- `CODEGEEX_VERSION`: CodeGeeX version (default: latest)
- `CODEGEEX_PORT`: API service port (default: 8000)

**Test Status**: ⏳ Not Tested

**Description**: CodeGeeX is an AI code generation tool developed by Tsinghua University, supporting multiple programming languages. Requires GPU support.

---

### Codeium ⏳ Not Tested

**Function**: AI code assistant, provides code completion and suggestions.

**Docker Image**: `codeium/codeium:latest`

**Configuration Options**:
- `CODEIUM_VERSION`: Codeium version (default: latest)
- `CODEIUM_PORT`: Web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Codeium is an AI code assistant that provides GitHub Copilot-like functionality.

---

### Tabby ⏳ Not Tested

**Function**: AI code completion tool, supports multiple editors.

**Docker Image**: `tabby/tabby:latest`

**Configuration Options**:
- `TABBY_VERSION`: Tabby version (default: latest)
- `TABBY_PORT`: API service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: Tabby is an open-source AI code completion tool that can be self-hosted.

---

## Vector Databases

### Chroma ✅ Tested and Passed

**Function**: Open-source vector database for storing and retrieving vector data.

**Docker Image**: `chromadb/chroma:latest`

**Configuration Options**:
- `CHROMA_VERSION`: Chroma version (default: latest)
- `CHROMA_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: Chroma is a lightweight vector database suitable for small to medium-scale vector retrieval scenarios, commonly used in RAG applications.

---

### Qdrant ✅ Tested and Passed

**Function**: High-performance vector search engine, supports large-scale vector retrieval.

**Docker Image**: `qdrant/qdrant:latest`

**Configuration Options**:
- `QDRANT_VERSION`: Qdrant version (default: latest)
- `QDRANT_PORT`: API service port (default: 6333)

**Test Status**: ✅ Tested and Passed

**Description**: Qdrant is a high-performance vector search engine that supports large-scale vector retrieval and similarity search, suitable for production environments.

---

### Weaviate ✅ Tested and Passed

**Function**: Vector database with semantic search and GraphQL API support.

**Docker Image**: `semitechnologies/weaviate:latest`

**Configuration Options**:
- `WEAVIATE_VERSION`: Weaviate version (default: latest)
- `WEAVIATE_PORT`: API service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Weaviate is a powerful vector database that supports semantic search and GraphQL API, suitable for building knowledge graph applications.

---

### Pinecone Alternative ✅ Tested and Passed

**Function**: Open-source alternative to Pinecone, vector database.

**Docker Image**: `pinecone/pinecone-alternative:latest`

**Configuration Options**:
- `PINECONE_VERSION`: Pinecone Alternative version (default: latest)
- `PINECONE_PORT`: API service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: Pinecone Alternative provides Pinecone-like functionality that can be self-hosted without relying on cloud services.

---

### Milvus ❌ Test Failed

**Function**: Large-scale vector database, supports distributed deployment.

**Docker Image**: `milvusdb/milvus:latest`

**Configuration Options**:
- `MILVUS_VERSION`: Milvus version (default: latest)
- `MILVUS_PORT`: API service port (default: 19530)

**Test Status**: ❌ Test Failed - `manifest for quay.io/coreos/etcd:v3.5 not found: manifest unknown`

**Description**: Milvus is a large-scale vector database, but the current etcd image version dependency does not exist.

---

## Other AI Tools

### TorchServe ✅ Tested and Passed

**Function**: PyTorch model serving framework for deploying PyTorch models.

**Docker Image**: `pytorch/torchserve:latest`

**Configuration Options**:
- `TORCHSERVE_VERSION`: TorchServe version (default: latest)
- `TORCHSERVE_PORT`: API service port (default: 8080)

**Test Status**: ✅ Tested and Passed (GPU server tested, took 1 minute 40 seconds)

**Description**: TorchServe is the official PyTorch model serving framework that makes it easy to deploy PyTorch models. Requires GPU support.

---

### Transformers ❌ Test Failed

**Function**: Hugging Face Transformers model inference service.

**Docker Image**: `huggingface/transformers:latest`

**Configuration Options**:
- `TRANSFORMERS_VERSION`: Transformers version (default: latest)
- `TRANSFORMERS_PORT`: API service port (default: 8000)

**Test Status**: ❌ Test Failed - `pull access denied for huggingface/transformers, repository does not exist or may require 'docker login'`

**Description**: Transformers image does not exist or requires special authentication.

---

### Replicate Proxy ⏳ Not Tested

**Function**: Replicate model proxy service, unified access to Replicate models.

**Docker Image**: `replicate/proxy:latest`

**Configuration Options**:
- `REPLICATE_PROXY_VERSION`: Replicate Proxy version (default: latest)
- `REPLICATE_PROXY_PORT`: API service port (default: 8080)
- `REPLICATE_API_TOKEN`: Replicate API Token (required)

**Test Status**: ⏳ Not Tested

**Description**: Replicate Proxy provides a unified interface to access various models on the Replicate platform. Requires Replicate API Token.

---

## Summary

The AI Applications category contains **76 templates**, of which:
- ✅ **Tested and Passed**: 20 templates
- ⏳ **Not Tested**: 50+ templates
- ❌ **Test Failed**: 4 templates
- ⚠️ **Unavailable**: 2 templates (translation templates)

Most GPU-related templates have been tested on GPU servers and performed well. Untested templates are mainly due to Docker Hub rate limits or image access issues.

---

*Last updated: 2025-11-11*
