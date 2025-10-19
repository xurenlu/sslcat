#!/bin/bash

# 为所有语言文件添加缺失的翻译键

languages=("zh-tw" "ja-jp" "es-es" "fr-fr" "ko-kr" "de-de" "ru-ru")

# 为每个语言文件添加缺失的翻译键
for lang in "${languages[@]}"; do
  echo "Updating $lang..."
  
  # 添加 unknownError 到 common 部分
  sed -i '/unknown: /a\    unknownError: '\''未知错误'\'',' "frontend/src/i18n/languages/$lang.ts"
  
  # 为 users 部分添加缺失的翻译键
  cat >> temp_users_$lang.txt << EOF
    passwordMinLength: '密码长度至少6位',
    passwordMustContainLetter: '密码必须包含至少一个字母',
    passwordMustContainNumber: '密码必须包含至少一个数字',
    passwordRequirements: '密码要求：至少6位，包含字母和数字',
    changingPassword: '修改中...',
    securityTips: '安全提示',
    reLoginAfterChange: '修改密码后需要重新登录',
    useStrongPassword: '建议使用强密码并定期更换',
    dontReusePassword: '不要在多个账户间使用相同密码',
    addUser: '添加用户',
    createUser: '创建用户',
    usernamePlaceholder: '输入用户名（至少3个字符）',
    password: '密码',
    passwordPlaceholder: '输入密码（至少6个字符）',
    email: '邮箱',
    emailPlaceholder: '输入邮箱地址',
    userCreated: '用户创建成功',
    userCreateFailed: '创建用户失败',
    userUpdated: '用户更新成功',
    userUpdateFailed: '用户更新失败',
    userDeleted: '用户删除成功',
    userDeleteFailed: '用户删除失败',
EOF

  # 为 imageOptimization 部分添加缺失的翻译键
  cat >> temp_image_$lang.txt << EOF
    loadConfigFailed: '加载配置失败',
    saveSuccess: '保存成功',
    saveFailed: '保存失败',
    cacheCleared: '缓存已清空',
    clearFailed: '清空失败',
    cacheHitRate: '缓存命中率',
    bandwidthSaved: '节省带宽',
    cacheSize: '缓存大小',
    items: '个项目',
    basicSettings: '基础设置',
    enableImageOptimization: '启用图片优化',
    autoConvertWebP: '自动转换为 WebP',
    removeMetadata: '移除图片元数据（EXIF）',
    compressionQuality: '压缩质量',
    webpQualityRecommendation: '推荐值：80（质量与大小的最佳平衡）',
    jpegQualityRecommendation: '推荐值：85（视觉无损）',
    pngCompressionRecommendation: '推荐值：6（平衡压缩率和速度）',
    sizeAdjustment: '尺寸调整',
    sizeInputPlaceholder: '输入尺寸，如 800',
    allowedSizesDescription: '用户只能请求这些尺寸，防止滥用。如：/image.jpg?width=800',
    cacheSettings: '缓存设置',
    enableCache: '启用缓存',
    cacheTTLRecommendation: '推荐值：86400（24小时）',
    maxCacheSizeRecommendation: '推荐值：1024（1GB）',
    clearImageCache: '清空图片缓存',
    pathFiltering: '路径过滤',
    includePatternPlaceholder: '如: *.jpg 或 /images/*',
    excludePatternPlaceholder: '如: /admin/* 或 /api/*',
    adjustWidth: '调整宽度为 800px',
    adjustHeight: '调整高度为 600px',
    specifyQuality: '指定质量',
    specifyFormat: '指定输出格式',
    bandwidthSavedJPEG: '节省 30-50% 带宽',
    bandwidthSavedPNG: '节省 40-70% 带宽',
    bandwidthSavedMobile: '节省 80-95% 带宽（移动端）',
EOF

  # 将翻译键添加到文件
  sed -i '/confirmPasswordPlaceholder: /r temp_users_$lang.txt' "frontend/src/i18n/languages/$lang.ts"
  sed -i '/saving: /r temp_image_$lang.txt' "frontend/src/i18n/languages/$lang.ts"
  
  # 清理临时文件
  rm -f temp_users_$lang.txt temp_image_$lang.txt
done

echo "All language files updated successfully!"
