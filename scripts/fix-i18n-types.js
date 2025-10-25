#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// 需要添加的字段
const additions = {
  common: {
    creating: '创建中...',
    saving: '保存中...'
  },
  proxy: {
    username: '用户名',
    password: '密码',
    performance_monitoring: '性能监控配置',
    enable_tracing: '启用请求追踪',
    enable_metrics: '启用指标收集',
    tracing_warning: '⚠️ 启用后会显著增加 CPU 占用，建议仅在调试时使用',
    metrics_warning: '⚠️ 启用后会增加 CPU 占用，建议仅在需要监控时使用'
  },
  sites: {
    edit: '编辑',
    delete: '删除'
  },
  dns: {
    cloudflare_name_placeholder: '我的 Cloudflare',
    api_key_placeholder: 'API 密钥',
    zone_id_placeholder: 'Zone ID (Cloudflare等需要)',
    api_key_update_placeholder: 'API 密钥（留空则不更新）'
  },
  notifications: {
    title_placeholder: '请输入通知标题',
    message_placeholder: '请输入通知消息'
  },
  settings: {
    save_success: '所有设置保存成功',
    save_failed: '保存失败',
    reset_success: '设置已重置',
    admin_prefix_change_success: 'Admin Prefix更改成功',
    admin_prefix_change_failed: 'Admin Prefix更改失败',
    admin_prefix_changed: '管理面板前缀已更改为',
    notification_sent: '通知已发送',
    basic_config_load_failed: '加载基础配置失败',
    notification_config_load_failed: '加载通知配置失败',
    basic_config_save_failed: '基础设置保存失败',
    notification_config_save_failed: '通知设置保存失败',
    select_min_notification_level: '选择最小通知级别',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx 或 https://qyapi.weixin.qq.com/xxx'
  }
};

// 翻译映射
const translations = {
  'en-US': {
    common: {
      creating: 'Creating...',
      saving: 'Saving...'
    },
    proxy: {
      username: 'Username',
      password: 'Password',
      performance_monitoring: 'Performance Monitoring',
      enable_tracing: 'Enable Request Tracing',
      enable_metrics: 'Enable Metrics Collection',
      tracing_warning: '⚠️ Enabling will significantly increase CPU usage, recommended for debugging only',
      metrics_warning: '⚠️ Enabling will increase CPU usage, recommended for monitoring only'
    },
    sites: {
      edit: 'Edit',
      delete: 'Delete'
    },
    dns: {
      cloudflare_name_placeholder: 'My Cloudflare',
      api_key_placeholder: 'API Key',
      zone_id_placeholder: 'Zone ID (required for Cloudflare etc.)',
      api_key_update_placeholder: 'API Key (leave empty to not update)'
    },
    notifications: {
      title_placeholder: 'Enter notification title',
      message_placeholder: 'Enter notification message'
    },
    settings: {
      save_success: 'All settings saved successfully',
      save_failed: 'Save failed',
      reset_success: 'Settings reset',
      admin_prefix_change_success: 'Admin Prefix changed successfully',
      admin_prefix_change_failed: 'Admin Prefix change failed',
      admin_prefix_changed: 'Admin panel prefix changed to',
      notification_sent: 'Notification sent',
      basic_config_load_failed: 'Failed to load basic configuration',
      notification_config_load_failed: 'Failed to load notification configuration',
      basic_config_save_failed: 'Basic settings save failed',
      notification_config_save_failed: 'Notification settings save failed',
      select_min_notification_level: 'Select minimum notification level',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx or https://qyapi.weixin.qq.com/xxx'
    }
  },
  'zh-TW': {
    common: {
      creating: '創建中...',
      saving: '保存中...'
    },
    proxy: {
      username: '用戶名',
      password: '密碼',
      performance_monitoring: '性能監控配置',
      enable_tracing: '啟用請求追蹤',
      enable_metrics: '啟用指標收集',
      tracing_warning: '⚠️ 啟用後會顯著增加 CPU 佔用，建議僅在調試時使用',
      metrics_warning: '⚠️ 啟用後會增加 CPU 佔用，建議僅在需要監控時使用'
    },
    sites: {
      edit: '編輯',
      delete: '刪除'
    },
    dns: {
      cloudflare_name_placeholder: '我的 Cloudflare',
      api_key_placeholder: 'API 密鑰',
      zone_id_placeholder: 'Zone ID (Cloudflare等需要)',
      api_key_update_placeholder: 'API 密鑰（留空則不更新）'
    },
    notifications: {
      title_placeholder: '請輸入通知標題',
      message_placeholder: '請輸入通知消息'
    },
    settings: {
      save_success: '所有設置保存成功',
      save_failed: '保存失敗',
      reset_success: '設置已重置',
      admin_prefix_change_success: 'Admin Prefix更改成功',
      admin_prefix_change_failed: 'Admin Prefix更改失敗',
      admin_prefix_changed: '管理面板前綴已更改為',
      notification_sent: '通知已發送',
      basic_config_load_failed: '加載基礎配置失敗',
      notification_config_load_failed: '加載通知配置失敗',
      basic_config_save_failed: '基礎設置保存失敗',
      notification_config_save_failed: '通知設置保存失敗',
      select_min_notification_level: '選擇最小通知級別',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx 或 https://qyapi.weixin.qq.com/xxx'
    }
  }
};

// 其他语言的简单翻译（使用英文作为基础）
const otherLanguages = ['de-DE', 'es-ES', 'fr-FR', 'ja-JP', 'ko-KR', 'ru-RU'];

function updateLanguageFile(filePath, language) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    
    // 获取翻译数据
    const translationData = translations[language] || translations['en-US'];
    
    // 更新数据
    Object.keys(additions).forEach(section => {
      if (!data[section]) {
        data[section] = {};
      }
      Object.keys(additions[section]).forEach(key => {
        data[section][key] = translationData[section][key];
      });
    });
    
    // 写回文件
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated ${filePath}`);
  } catch (error) {
    console.error(`Error updating ${filePath}:`, error.message);
  }
}

// 更新所有语言文件
const languages = ['zh-CN', 'en-US', 'zh-TW', 'de-DE', 'es-ES', 'fr-FR', 'ja-JP', 'ko-KR', 'ru-RU'];

languages.forEach(lang => {
  const filePath = path.join(__dirname, '..', 'i18n', `${lang}.json`);
  if (fs.existsSync(filePath)) {
    updateLanguageFile(filePath, lang);
  }
});

console.log('All language files updated!');
