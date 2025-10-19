import { Translation } from './languages/types';
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