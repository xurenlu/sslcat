import { Translation } from './languages/types';
import { zhCN } from './languages/zh-cn';
import { enUS } from './languages/en-us';
import { jaJP } from './languages/ja-jp';
import { esES } from './languages/es-es';
import { frFR } from './languages/fr-fr';
import { deDE } from './languages/de-de';

export const translations: Record<string, Translation> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'ja-JP': jaJP,
  'es-ES': esES,
  'fr-FR': frFR,
  'de-DE': deDE,
};

export const getTranslation = (languageCode: string): Translation => {
  return translations[languageCode] || translations['zh-CN'];
};

export type { Translation };