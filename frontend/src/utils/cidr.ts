/**
 * CIDR 类型识别和描述工具函数
 */

/**
 * 获取CIDR类型描述
 * @param cidr CIDR格式的IP地址或网段，如 "192.168.1.1" 或 "192.168.1.0/24"
 * @returns CIDR类型描述（中文）
 */
export function getCIDRTypeDescription(cidr: string): string {
  if (!cidr) {
    return '未知'
  }

  // 检查是否包含斜杠
  if (!cidr.includes('/')) {
    return '单个IP'
  }

  const parts = cidr.split('/')
  if (parts.length !== 2) {
    return '其他网段'
  }

  const maskStr = parts[1]
  const mask = parseInt(maskStr, 10)

  if (isNaN(mask)) {
    return '其他网段'
  }

  switch (mask) {
    case 32:
      return '单个IP'
    case 24:
      return 'C段'
    case 16:
      return 'B段'
    case 8:
      return 'A段'
    default:
      if (mask > 24 && mask < 32) {
        return `/${mask}网段`
      } else if (mask > 16 && mask < 24) {
        return `/${mask}网段`
      } else if (mask > 8 && mask < 16) {
        return `/${mask}网段`
      } else {
        return `/${mask}网段`
      }
  }
}

/**
 * 获取CIDR类型对应的颜色标签（用于Badge组件）
 * @param cidr CIDR格式的IP地址或网段
 * @returns Chakra UI Badge的colorScheme值
 */
export function getCIDRTypeColor(cidr: string): string {
  const type = getCIDRTypeDescription(cidr)
  
  switch (type) {
    case '单个IP':
      return 'blue'
    case 'C段':
      return 'green'
    case 'B段':
      return 'orange'
    case 'A段':
      return 'red'
    default:
      return 'gray'
  }
}

