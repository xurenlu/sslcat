// 国际化配置文件
export interface Translation {
  // 通用
  common: {
    save: string
    cancel: string
    delete: string
    edit: string
    add: string
    refresh: string
    loading: string
    success: string
    error: string
    warning: string
    confirm: string
    close: string
  }
  
  // 导航菜单
  navigation: {
    dashboard: string
    proxy: string
    sites: string
    ssl: string
    settings: string
    dns: string
    security: string
    gitServer: string
    notifications: string
    advanced: string
    logout: string
  }
  
  // 仪表板
  dashboard: {
    title: string
    activeRules: string
    cachedProxies: string
    publicIP: string
    goVersion: string
    systemStatus: string
    sslStatus: string
    proxyStatus: string
    quickActions: string
  }
  
  // 代理管理
  proxy: {
    title: string
    addRule: string
    editRule: string
    deleteRule: string
    enableRule: string
    disableRule: string
    noRules: string
    createFirst: string
  }
  
  // SSL证书
  ssl: {
    title: string
    addCertificate: string
    renewCertificate: string
    deleteCertificate: string
    noCertificates: string
    createFirst: string
  }
  
  // 通知管理
  notifications: {
    title: string
    sendTest: string
    testChannels: string
    noNotifications: string
  }
}

// 中文翻译
export const zhCN: Translation = {
  common: {
    save: '保存',
    cancel: '取消',
    delete: '删除',
    edit: '编辑',
    add: '添加',
    refresh: '刷新',
    loading: '加载中...',
    success: '成功',
    error: '错误',
    warning: '警告',
    confirm: '确认',
    close: '关闭',
  },
  navigation: {
    dashboard: '仪表板',
    proxy: '代理配置',
    sites: '站点管理',
    ssl: 'SSL证书',
    settings: '系统设置',
    dns: 'DNS配置',
    security: '安全设置',
    gitServer: 'Git部署服务器',
    notifications: '通知管理',
    advanced: '高级选项',
    logout: '退出登录',
  },
  dashboard: {
    title: '仪表板',
    activeRules: '活跃规则',
    cachedProxies: '缓存代理',
    publicIP: '公网IP',
    goVersion: 'Go版本',
    systemStatus: '系统状态',
    sslStatus: 'SSL证书状态良好',
    proxyStatus: '代理服务正常',
    quickActions: '快速操作',
  },
  proxy: {
    title: '代理配置',
    addRule: '添加规则',
    editRule: '编辑规则',
    deleteRule: '删除规则',
    enableRule: '启用规则',
    disableRule: '禁用规则',
    noRules: '暂无代理规则',
    createFirst: '创建第一个规则',
  },
  ssl: {
    title: 'SSL证书管理',
    addCertificate: '添加证书',
    renewCertificate: '更新证书',
    deleteCertificate: '删除证书',
    noCertificates: '暂无SSL证书',
    createFirst: '创建第一个证书',
  },
  notifications: {
    title: '通知管理',
    sendTest: '发送测试通知',
    testChannels: '测试通知渠道',
    noNotifications: '暂无通知记录',
  },
}

// 英文翻译
export const enUS: Translation = {
  common: {
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    edit: 'Edit',
    add: 'Add',
    refresh: 'Refresh',
    loading: 'Loading...',
    success: 'Success',
    error: 'Error',
    warning: 'Warning',
    confirm: 'Confirm',
    close: 'Close',
  },
  navigation: {
    dashboard: 'Dashboard',
    proxy: 'Proxy',
    sites: 'Sites',
    ssl: 'SSL',
    settings: 'Settings',
    dns: 'DNS',
    security: 'Security',
    gitServer: 'Git Server',
    notifications: 'Notifications',
    advanced: 'Advanced',
    logout: 'Logout',
  },
  dashboard: {
    title: 'Dashboard',
    activeRules: 'Active Rules',
    cachedProxies: 'Cached Proxies',
    publicIP: 'Public IP',
    goVersion: 'Go Version',
    systemStatus: 'System Status',
    sslStatus: 'SSL certificates are in good condition',
    proxyStatus: 'Proxy service is running normally',
    quickActions: 'Quick Actions',
  },
  proxy: {
    title: 'Proxy Configuration',
    addRule: 'Add Rule',
    editRule: 'Edit Rule',
    deleteRule: 'Delete Rule',
    enableRule: 'Enable Rule',
    disableRule: 'Disable Rule',
    noRules: 'No proxy rules',
    createFirst: 'Create first rule',
  },
  ssl: {
    title: 'SSL Certificate Management',
    addCertificate: 'Add Certificate',
    renewCertificate: 'Renew Certificate',
    deleteCertificate: 'Delete Certificate',
    noCertificates: 'No SSL certificates',
    createFirst: 'Create first certificate',
  },
  notifications: {
    title: 'Notification Management',
    sendTest: 'Send Test Notification',
    testChannels: 'Test Notification Channels',
    noNotifications: 'No notification records',
  },
}

// 翻译映射
export const translations: Record<string, Translation> = {
  'zh-CN': zhCN,
  'zh-TW': zhCN, // 暂时使用简体中文
  'en-US': enUS,
  'ja-JP': enUS, // 暂时使用英文
  'ko-KR': enUS, // 暂时使用英文
  'es-ES': enUS, // 暂时使用英文
  'fr-FR': enUS, // 暂时使用英文
  'de-DE': enUS, // 暂时使用英文
  'ru-RU': enUS, // 暂时使用英文
}

// 获取翻译函数
export const getTranslation = (languageCode: string): Translation => {
  return translations[languageCode] || translations['zh-CN']
}
