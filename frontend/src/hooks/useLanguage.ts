import { useState, useEffect } from 'react'

export interface Language {
  code: string
  name: string
  nativeName: string
  flag: string
}

export const supportedLanguages: Language[] = [
  { code: 'zh-CN', name: '简体中文', nativeName: '简体中文', flag: '🇨🇳' },
  { code: 'zh-TW', name: '繁體中文', nativeName: '繁體中文', flag: '🇹🇼' },
  { code: 'en-US', name: 'English', nativeName: 'English', flag: '🇺🇸' },
  { code: 'ja-JP', name: '日本語', nativeName: '日本語', flag: '🇯🇵' },
  { code: 'ko-KR', name: '한국어', nativeName: '한국어', flag: '🇰🇷' },
  { code: 'es-ES', name: 'Español', nativeName: 'Español', flag: '🇪🇸' },
  { code: 'fr-FR', name: 'Français', nativeName: 'Français', flag: '🇫🇷' },
  { code: 'de-DE', name: 'Deutsch', nativeName: 'Deutsch', flag: '🇩🇪' },
  { code: 'ru-RU', name: 'Русский', nativeName: 'Русский', flag: '🇷🇺' },
]

export const useLanguage = () => {
  const [currentLanguage, setCurrentLanguage] = useState<string>('zh-CN')

  useEffect(() => {
    // 从 localStorage 读取保存的语言设置
    const savedLanguage = localStorage.getItem('withssl-language')
    if (savedLanguage && supportedLanguages.find(lang => lang.code === savedLanguage)) {
      setCurrentLanguage(savedLanguage)
    } else {
      // 检测浏览器语言
      const browserLanguage = navigator.language
      const matchedLanguage = supportedLanguages.find(lang => 
        browserLanguage.startsWith(lang.code.split('-')[0])
      )
      if (matchedLanguage) {
        setCurrentLanguage(matchedLanguage.code)
      }
    }
  }, [])

  const changeLanguage = (languageCode: string) => {
    setCurrentLanguage(languageCode)
    localStorage.setItem('withssl-language', languageCode)
    
    // TODO: 实现实际的国际化切换
    console.log('Language changed to:', languageCode)
    
    // 这里可以触发全局状态更新或重新加载页面
    // window.location.reload() // 如果需要重新加载页面
  }

  const getCurrentLanguage = () => {
    return supportedLanguages.find(lang => lang.code === currentLanguage) || supportedLanguages[0]
  }

  return {
    currentLanguage,
    changeLanguage,
    getCurrentLanguage,
    supportedLanguages,
  }
}
