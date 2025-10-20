import { useToast } from '@chakra-ui/react'
import { useTranslation } from './useLanguage'

export interface ToastOptions {
  title?: string
  description?: string
  status?: 'success' | 'error' | 'warning' | 'info'
  duration?: number
  isClosable?: boolean
}

export const useToastMessages = () => {
  const toast = useToast()
  const t = useTranslation()

  const showToast = (options: ToastOptions) => {
    toast({
      title: options.title || t.toast.success,
      description: options.description,
      status: options.status || 'success',
      duration: options.duration || 3000,
      isClosable: options.isClosable !== false,
    })
  }

  // 通用成功消息
  const showSuccess = (message: string, description?: string) => {
    showToast({
      title: message,
      description,
      status: 'success',
    })
  }

  // 通用错误消息
  const showError = (message: string, description?: string) => {
    showToast({
      title: message,
      description,
      status: 'error',
    })
  }

  // 通用警告消息
  const showWarning = (message: string, description?: string) => {
    showToast({
      title: message,
      description,
      status: 'warning',
    })
  }

  // 通用信息消息
  const showInfo = (message: string, description?: string) => {
    showToast({
      title: message,
      description,
      status: 'info',
    })
  }

  // 站点管理相关
  const siteDeleteSuccess = () => showSuccess(t.toast.siteDeleteSuccess)
  const siteDeleteFailed = (error?: string) => showError(t.toast.siteDeleteFailed, error)
  const siteCreateSuccess = () => showSuccess(t.toast.siteCreateSuccess)
  const siteCreateFailed = (error?: string) => showError(t.toast.siteCreateFailed, error)
  const siteUpdateSuccess = () => showSuccess(t.toast.siteUpdateSuccess)
  const siteUpdateFailed = (error?: string) => showError(t.toast.siteUpdateFailed, error)
  const siteDataLoadFailed = (error?: string) => showError(t.toast.siteDataLoadFailed, error)
  const siteDataLoadPartialFailed = () => showWarning(t.toast.siteDataLoadPartialFailed, t.toast.siteDataLoadPartialFailedDesc)

  // 代理管理相关
  const proxyDeleteSuccess = () => showSuccess(t.toast.proxyDeleteSuccess)
  const proxyDeleteFailed = (error?: string) => showError(t.toast.proxyDeleteFailed, error)
  const proxyCreateSuccess = () => showSuccess(t.toast.proxyCreateSuccess)
  const proxyCreateFailed = (error?: string) => showError(t.toast.proxyCreateFailed, error)
  const proxyUpdateSuccess = () => showSuccess(t.toast.proxyUpdateSuccess)
  const proxyUpdateFailed = (error?: string) => showError(t.toast.proxyUpdateFailed, error)

  // SSL 管理相关
  const sslCertRenewSuccess = () => showSuccess(t.toast.sslCertRenewSuccess)
  const sslCertRenewFailed = (error?: string) => showError(t.toast.sslCertRenewFailed, error)
  const sslCertDeleteSuccess = () => showSuccess(t.toast.sslCertDeleteSuccess)
  const sslCertDeleteFailed = (error?: string) => showError(t.toast.sslCertDeleteFailed, error)
  const sslCertSyncSuccess = () => showSuccess(t.toast.sslCertSyncSuccess)
  const sslCertSyncFailed = (error?: string) => showError(t.toast.sslCertSyncFailed, error)

  // 用户管理相关
  const userCreateSuccess = () => showSuccess(t.toast.userCreateSuccess)
  const userCreateFailed = (error?: string) => showError(t.toast.userCreateFailed, error)
  const userUpdateSuccess = () => showSuccess(t.toast.userUpdateSuccess)
  const userUpdateFailed = (error?: string) => showError(t.toast.userUpdateFailed, error)
  const userDeleteSuccess = () => showSuccess(t.toast.userDeleteSuccess)
  const userDeleteFailed = (error?: string) => showError(t.toast.userDeleteFailed, error)
  const userPasswordChangeSuccess = () => showSuccess(t.toast.userPasswordChangeSuccess)
  const userPasswordChangeFailed = (error?: string) => showError(t.toast.userPasswordChangeFailed, error)

  // 系统设置相关
  const settingsSaveSuccess = () => showSuccess(t.toast.settingsSaveSuccess)
  const settingsSaveFailed = (error?: string) => showError(t.toast.settingsSaveFailed, error)
  const passwordChangeSuccess = () => showSuccess(t.toast.passwordChangeSuccess)
  const passwordChangeFailed = (error?: string) => showError(t.toast.passwordChangeFailed, error)

  // 集群管理相关
  const clusterSyncSuccess = () => showSuccess(t.toast.clusterSyncSuccess)
  const clusterSyncFailed = (error?: string) => showError(t.toast.clusterSyncFailed, error)
  const clusterMasterReachable = () => showSuccess(t.toast.clusterMasterReachable)
  const clusterMasterUnreachable = () => showError(t.toast.clusterMasterUnreachable)

  // DNS 管理相关
  const dnsRecordCreateSuccess = () => showSuccess(t.toast.dnsRecordCreateSuccess)
  const dnsRecordCreateFailed = (error?: string) => showError(t.toast.dnsRecordCreateFailed, error)
  const dnsRecordUpdateSuccess = () => showSuccess(t.toast.dnsRecordUpdateSuccess)
  const dnsRecordUpdateFailed = (error?: string) => showError(t.toast.dnsRecordUpdateFailed, error)
  const dnsRecordDeleteSuccess = () => showSuccess(t.toast.dnsRecordDeleteSuccess)
  const dnsRecordDeleteFailed = (error?: string) => showError(t.toast.dnsRecordDeleteFailed, error)

  // 通知管理相关
  const notificationCreateSuccess = () => showSuccess(t.toast.notificationCreateSuccess)
  const notificationCreateFailed = (error?: string) => showError(t.toast.notificationCreateFailed, error)
  const notificationUpdateSuccess = () => showSuccess(t.toast.notificationUpdateSuccess)
  const notificationUpdateFailed = (error?: string) => showError(t.toast.notificationUpdateFailed, error)
  const notificationDeleteSuccess = () => showSuccess(t.toast.notificationDeleteSuccess)
  const notificationDeleteFailed = (error?: string) => showError(t.toast.notificationDeleteFailed, error)
  const notificationTestSuccess = () => showSuccess(t.toast.notificationTestSuccess)
  const notificationTestFailed = (error?: string) => showError(t.toast.notificationTestFailed, error)

  // 安全设置相关
  const securitySettingsUpdateSuccess = () => showSuccess(t.toast.securitySettingsUpdateSuccess)
  const securitySettingsUpdateFailed = (error?: string) => showError(t.toast.securitySettingsUpdateFailed, error)
  const ipBlockSuccess = () => showSuccess(t.toast.ipBlockSuccess)
  const ipBlockFailed = (error?: string) => showError(t.toast.ipBlockFailed, error)
  const ipUnblockSuccess = () => showSuccess(t.toast.ipUnblockSuccess)
  const ipUnblockFailed = (error?: string) => showError(t.toast.ipUnblockFailed, error)

  // 图片优化相关
  const imageOptimizationSuccess = () => showSuccess(t.toast.imageOptimizationSuccess)
  const imageOptimizationFailed = (error?: string) => showError(t.toast.imageOptimizationFailed, error)
  const imageOptimizationSettingsUpdateSuccess = () => showSuccess(t.toast.imageOptimizationSettingsUpdateSuccess)
  const imageOptimizationSettingsUpdateFailed = (error?: string) => showError(t.toast.imageOptimizationSettingsUpdateFailed, error)

  // Git 服务器相关
  const gitServerStartSuccess = () => showSuccess(t.toast.gitServerStartSuccess)
  const gitServerStartFailed = (error?: string) => showError(t.toast.gitServerStartFailed, error)
  const gitServerStopSuccess = () => showSuccess(t.toast.gitServerStopSuccess)
  const gitServerStopFailed = (error?: string) => showError(t.toast.gitServerStopFailed, error)
  const gitAppCreateSuccess = () => showSuccess(t.toast.gitAppCreateSuccess)
  const gitAppCreateFailed = (error?: string) => showError(t.toast.gitAppCreateFailed, error)
  const gitAppDeleteSuccess = () => showSuccess(t.toast.gitAppDeleteSuccess)
  const gitAppDeleteFailed = (error?: string) => showError(t.toast.gitAppDeleteFailed, error)
  const gitAppRedeploySuccess = () => showSuccess(t.toast.gitAppRedeploySuccess)
  const gitAppRedeployFailed = (error?: string) => showError(t.toast.gitAppRedeployFailed, error)

  // 统计信息相关
  const statisticsLoadSuccess = () => showSuccess(t.toast.statisticsLoadSuccess)
  const statisticsLoadFailed = (error?: string) => showError(t.toast.statisticsLoadFailed, error)

  // 日志管理相关
  const logLoadSuccess = () => showSuccess(t.toast.logLoadSuccess)
  const logLoadFailed = (error?: string) => showError(t.toast.logLoadFailed, error)
  const logClearSuccess = () => showSuccess(t.toast.logClearSuccess)
  const logClearFailed = (error?: string) => showError(t.toast.logClearFailed, error)

  // 配置测试相关
  const configTestSuccess = () => showSuccess(t.toast.configTestSuccess)
  const configTestFailed = (error?: string) => showError(t.toast.configTestFailed, error)
  const configTestWarning = (message?: string) => showWarning(t.toast.configTestWarning, message)

  // 网络错误相关
  const networkError = (error?: string) => showError(t.toast.networkError, error)
  const networkTimeout = (error?: string) => showError(t.toast.networkTimeout, error)
  const serverError = (error?: string) => showError(t.toast.serverError, error)
  const unknownError = (error?: string) => showError(t.toast.unknownError, error)

  return {
    // 通用方法
    showToast,
    showSuccess,
    showError,
    showWarning,
    showInfo,
    
    // 站点管理
    siteDeleteSuccess,
    siteDeleteFailed,
    siteCreateSuccess,
    siteCreateFailed,
    siteUpdateSuccess,
    siteUpdateFailed,
    siteDataLoadFailed,
    siteDataLoadPartialFailed,
    
    // 代理管理
    proxyDeleteSuccess,
    proxyDeleteFailed,
    proxyCreateSuccess,
    proxyCreateFailed,
    proxyUpdateSuccess,
    proxyUpdateFailed,
    
    // SSL 管理
    sslCertRenewSuccess,
    sslCertRenewFailed,
    sslCertDeleteSuccess,
    sslCertDeleteFailed,
    sslCertSyncSuccess,
    sslCertSyncFailed,
    
    // 用户管理
    userCreateSuccess,
    userCreateFailed,
    userUpdateSuccess,
    userUpdateFailed,
    userDeleteSuccess,
    userDeleteFailed,
    userPasswordChangeSuccess,
    userPasswordChangeFailed,
    
    // 系统设置
    settingsSaveSuccess,
    settingsSaveFailed,
    passwordChangeSuccess,
    passwordChangeFailed,
    
    // 集群管理
    clusterSyncSuccess,
    clusterSyncFailed,
    clusterMasterReachable,
    clusterMasterUnreachable,
    
    // DNS 管理
    dnsRecordCreateSuccess,
    dnsRecordCreateFailed,
    dnsRecordUpdateSuccess,
    dnsRecordUpdateFailed,
    dnsRecordDeleteSuccess,
    dnsRecordDeleteFailed,
    
    // 通知管理
    notificationCreateSuccess,
    notificationCreateFailed,
    notificationUpdateSuccess,
    notificationUpdateFailed,
    notificationDeleteSuccess,
    notificationDeleteFailed,
    notificationTestSuccess,
    notificationTestFailed,
    
    // 安全设置
    securitySettingsUpdateSuccess,
    securitySettingsUpdateFailed,
    ipBlockSuccess,
    ipBlockFailed,
    ipUnblockSuccess,
    ipUnblockFailed,
    
    // 图片优化
    imageOptimizationSuccess,
    imageOptimizationFailed,
    imageOptimizationSettingsUpdateSuccess,
    imageOptimizationSettingsUpdateFailed,
    
    // Git 服务器
    gitServerStartSuccess,
    gitServerStartFailed,
    gitServerStopSuccess,
    gitServerStopFailed,
    gitAppCreateSuccess,
    gitAppCreateFailed,
    gitAppDeleteSuccess,
    gitAppDeleteFailed,
    gitAppRedeploySuccess,
    gitAppRedeployFailed,
    
    // 统计信息
    statisticsLoadSuccess,
    statisticsLoadFailed,
    
    // 日志管理
    logLoadSuccess,
    logLoadFailed,
    logClearSuccess,
    logClearFailed,
    
    // 配置测试
    configTestSuccess,
    configTestFailed,
    configTestWarning,
    
    // 网络错误
    networkError,
    networkTimeout,
    serverError,
    unknownError,
  }
}
