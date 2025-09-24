#!/bin/bash

# 快速修复 TypeScript 导入问题
echo "🔧 修复 TypeScript 导入问题..."

cd frontend

# 移除未使用的导入
echo "📝 清理未使用的导入..."

# 修复 Layout.tsx
sed -i '' '/Flex,/d' src/components/Layout.tsx

# 修复 Dashboard.tsx
sed -i '' '/StatHelpText,/d' src/pages/Dashboard.tsx
sed -i '' '/Badge,/d' src/pages/Dashboard.tsx

# 修复 ClusterManagement.tsx
sed -i '' '/FiCheckCircle,/d' src/pages/ClusterManagement.tsx
sed -i '' '/FiXCircle,/d' src/pages/ClusterManagement.tsx
sed -i '' '/FiClock,/d' src/pages/ClusterManagement.tsx
sed -i '' '/FiPause,/d' src/pages/ClusterManagement.tsx

# 修复 DNSManagement.tsx
sed -i '' '/FiServer,/d' src/pages/DNSManagement.tsx
sed -i '' '/FiCheckCircle,/d' src/pages/DNSManagement.tsx

# 修复 GitServerManagement.tsx
sed -i '' '/CardHeader,/d' src/pages/GitServerManagement.tsx
sed -i '' '/Select,/d' src/pages/GitServerManagement.tsx
sed -i '' '/FiDownload,/d' src/pages/GitServerManagement.tsx

# 修复 ProxyList.tsx
sed -i '' '/Spinner,/d' src/pages/ProxyList.tsx

# 修复 RunnersManagement.tsx
sed -i '' '/CardHeader,/d' src/pages/RunnersManagement.tsx
sed -i '' '/FiUpload,/d' src/pages/RunnersManagement.tsx
sed -i '' '/FiSettings,/d' src/pages/RunnersManagement.tsx

# 修复 Settings.tsx
sed -i '' '/Divider,/d' src/pages/Settings.tsx
sed -i '' '/Textarea,/d' src/pages/Settings.tsx

# 修复 SitesManagement.tsx
sed -i '' '/SimpleGrid,/d' src/pages/SitesManagement.tsx
sed -i '' '/CardHeader,/d' src/pages/SitesManagement.tsx
sed -i '' '/Textarea,/d' src/pages/SitesManagement.tsx
sed -i '' '/FiServer,/d' src/pages/SitesManagement.tsx
sed -i '' '/FiSettings,/d' src/pages/SitesManagement.tsx

# 修复 SSLManagement.tsx
sed -i '' '/FiClock,/d' src/pages/SSLManagement.tsx

# 修复 api.ts
sed -i '' '/ApiResponse,/d' src/utils/api.ts

echo "✅ 导入清理完成！"

# 尝试构建
echo "🏗️ 尝试构建..."
pnpm run build

echo "🎉 修复完成！"
