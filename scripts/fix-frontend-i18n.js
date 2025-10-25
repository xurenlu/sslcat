#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// 需要添加的字段
const additions = {
  zh_cn: {
    select_min_notification_level: '选择最小通知级别',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx 或 https://qyapi.weixin.qq.com/xxx',
  },
  en_us: {
    select_min_notification_level: 'Select minimum notification level',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx or https://qyapi.weixin.qq.com/xxx',
  },
  zh_tw: {
    select_min_notification_level: '選擇最小通知級別',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx 或 https://qyapi.weixin.qq.com/xxx',
  },
  de_de: {
    select_min_notification_level: 'Mindestbenachrichtigungsstufe auswählen',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx oder https://qyapi.weixin.qq.com/xxx',
  },
  es_es: {
    select_min_notification_level: 'Seleccionar nivel mínimo de notificación',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx o https://qyapi.weixin.qq.com/xxx',
  },
  fr_fr: {
    select_min_notification_level: 'Sélectionner le niveau de notification minimum',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx ou https://qyapi.weixin.qq.com/xxx',
  },
  ja_jp: {
    select_min_notification_level: '最小通知レベルを選択',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx または https://qyapi.weixin.qq.com/xxx',
  },
  ko_kr: {
    select_min_notification_level: '최소 알림 수준 선택',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx 또는 https://qyapi.weixin.qq.com/xxx',
  },
  ru_ru: {
    select_min_notification_level: 'Выбрать минимальный уровень уведомлений',
    webhook_placeholder: 'https://hooks.slack.com/services/xxx или https://qyapi.weixin.qq.com/xxx',
  },
};

function updateTSFile(filePath, lang) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    
    // 获取对应的翻译
    const translationData = additions[lang];
    if (!translationData) {
      console.log(`No translation data for ${lang}`);
      return;
    }
    
    // 检查是否已经存在
    if (content.includes('select_min_notification_level') && content.includes('webhook_placeholder')) {
      console.log(`Already updated ${filePath}`);
      return;
    }
    
    // 找到settings的结尾位置并添加新字段
    const settingsEndPattern = /notification_config_save_failed:.*,?\s*(\},\s*sidebar:)/;
    const match = content.match(settingsEndPattern);
    
    if (match) {
      const newContent = content.replace(
        settingsEndPattern,
        `notification_config_save_failed: ${match[0].match(/notification_config_save_failed:.*,/)?.[0] || 'notification_config_save_failed: \'...\','},\n    select_min_notification_level: '${translationData.select_min_notification_level}',\n    webhook_placeholder: '${translationData.webhook_placeholder}',\n  },\n  sidebar:`
      );
      
      fs.writeFileSync(filePath, newContent);
      console.log(`Updated ${filePath}`);
    } else {
      console.log(`Could not find insertion point in ${filePath}`);
    }
  } catch (error) {
    console.error(`Error updating ${filePath}:`, error.message);
  }
}

// 更新所有语言文件
const languages = [
  { file: 'zh-cn.ts', lang: 'zh_cn' },
  { file: 'en-us.ts', lang: 'en_us' },
  { file: 'zh-tw.ts', lang: 'zh_tw' },
  { file: 'de-de.ts', lang: 'de_de' },
  { file: 'es-es.ts', lang: 'es_es' },
  { file: 'fr-fr.ts', lang: 'fr_fr' },
  { file: 'ja-jp.ts', lang: 'ja_jp' },
  { file: 'ko-kr.ts', lang: 'ko_kr' },
  { file: 'ru-ru.ts', lang: 'ru_ru' },
];

languages.forEach(({ file, lang }) => {
  const filePath = path.join(__dirname, '..', 'frontend', 'src', 'i18n', 'languages', file);
  if (fs.existsSync(filePath)) {
    updateTSFile(filePath, lang);
  }
});

console.log('All frontend language files updated!');
