#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const i18nFile = path.join(__dirname, '../frontend/src/i18n/index.ts');
const outputDir = path.join(__dirname, '../frontend/src/i18n/languages');

// 确保输出目录存在
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// 读取原始文件
const content = fs.readFileSync(i18nFile, 'utf8');

// 提取接口定义
const interfaceMatch = content.match(/export interface Translation \{[\s\S]*?\n\}/);
const interfaceContent = interfaceMatch ? interfaceMatch[0] : '';

// 创建接口文件
fs.writeFileSync(
  path.join(outputDir, 'types.ts'),
  `// 国际化类型定义
${interfaceContent}
`
);

// 语言映射
const languages = [
  { name: 'zhCN', code: 'zh-CN', file: 'zh-cn.ts' },
  { name: 'enUS', code: 'en-US', file: 'en-us.ts' },
  { name: 'jaJP', code: 'ja-JP', file: 'ja-jp.ts' },
  { name: 'esES', code: 'es-ES', file: 'es-es.ts' },
  { name: 'frFR', code: 'fr-FR', file: 'fr-fr.ts' },
  { name: 'koKR', code: 'ko-KR', file: 'ko-kr.ts' },
  { name: 'deDE', code: 'de-DE', file: 'de-de.ts' },
  { name: 'ruRU', code: 'ru-RU', file: 'ru-ru.ts' },
  { name: 'zhTW', code: 'zh-TW', file: 'zh-tw.ts' }
];

// 提取每个语言的翻译
languages.forEach(lang => {
  const regex = new RegExp(`export const ${lang.name}: Translation = \\{([\\s\\S]*?)\\n\\};`);
  const match = content.match(regex);
  
  if (match) {
    const translationContent = match[1];
    const fileContent = `import { Translation } from './types';

export const ${lang.name}: Translation = {${translationContent}
};
`;
    
    fs.writeFileSync(path.join(outputDir, lang.file), fileContent);
    console.log(`Created ${lang.file}`);
  }
});

// 创建主入口文件
const mainContent = `import { Translation } from './languages/types';
import { zhCN } from './languages/zh-cn';
import { enUS } from './languages/en-us';
import { jaJP } from './languages/ja-jp';
import { esES } from './languages/es-es';
import { frFR } from './languages/fr-fr';
import { koKR } from './languages/ko-kr';
import { deDE } from './languages/de-de';
import { ruRU } from './languages/ru-ru';
import { zhTW } from './languages/zh-tw';

export const translations: Record<string, Translation> = {
  'zh-CN': zhCN,
  'zh-TW': zhTW,
  'en-US': enUS,
  'ja-JP': jaJP,
  'ko-KR': koKR,
  'es-ES': esES,
  'fr-FR': frFR,
  'de-DE': deDE,
  'ru-RU': ruRU,
};

export const getTranslation = (languageCode: string): Translation => {
  return translations[languageCode] || translations['zh-CN'];
};

export type { Translation };
`;

fs.writeFileSync(path.join(__dirname, '../frontend/src/i18n/index.ts'), mainContent);
console.log('Created new index.ts');

console.log('i18n files split successfully!');
