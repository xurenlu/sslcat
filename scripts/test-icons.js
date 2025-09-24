#!/usr/bin/env node

// 测试 react-icons/fi 中的图标是否存在
const icons = [
  'FiHome', 'FiSettings', 'FiShield', 'FiGlobe', 'FiZap', 'FiBell',
  'FiChevronDown', 'FiChevronRight', 'FiTerminal', 'FiGitBranch',
  'FiUsers', 'FiLogOut', 'FiPlus', 'FiRefreshCw', 'FiEdit', 'FiTrash2',
  'FiServer', 'FiCheckCircle', 'FiDownload', 'FiClock', 'FiCheck', 'FiX',
  'FiList', 'FiSend', 'FiGithub', 'FiUpload', 'FiKey', 'FiFolder', 'FiCopy',
  'FiPlay', 'FiPause', 'FiStop', 'FiContainer', 'FiXCircle', 'FiAlertTriangle'
];

console.log('🔍 测试 react-icons/fi 图标...');

try {
  const reactIcons = require('react-icons/fi');
  
  console.log('✅ react-icons/fi 模块加载成功');
  
  const missingIcons = [];
  const availableIcons = [];
  
  icons.forEach(iconName => {
    if (reactIcons[iconName]) {
      availableIcons.push(iconName);
    } else {
      missingIcons.push(iconName);
    }
  });
  
  console.log(`\n📊 测试结果:`);
  console.log(`✅ 可用图标: ${availableIcons.length}/${icons.length}`);
  console.log(`❌ 缺失图标: ${missingIcons.length}`);
  
  if (availableIcons.length > 0) {
    console.log('\n✅ 可用图标:');
    availableIcons.forEach(icon => console.log(`  - ${icon}`));
  }
  
  if (missingIcons.length > 0) {
    console.log('\n❌ 缺失图标:');
    missingIcons.forEach(icon => console.log(`  - ${icon}`));
  }
  
  console.log('\n🎉 图标测试完成！');
  
} catch (error) {
  console.error('❌ 错误:', error.message);
  console.log('\n💡 请确保已安装 react-icons:');
  console.log('   pnpm install react-icons');
}
