import React, { useState, useEffect, createContext, useContext } from 'react'
import { getTranslation, Translation } from '../i18n'

export interface Language {
  code: string
  name: string
  nativeName: string
  flag: string
}

export const supportedLanguages: Language[] = [
  { code: 'zh-CN', name: '简体中文', nativeName: '简体中文', flag: '🇨🇳' },
  { code: 'en-US', name: 'English', nativeName: 'English', flag: '🇺🇸' },
  { code: 'ja-JP', name: '日本語', nativeName: '日本語', flag: '🇯🇵' },
  { code: 'es-ES', name: 'Español', nativeName: 'Español', flag: '🇪🇸' },
  { code: 'fr-FR', name: 'Français', nativeName: 'Français', flag: '🇫🇷' },
  { code: 'de-DE', name: 'Deutsch', nativeName: 'Deutsch', flag: '🇩🇪' },
]

// 创建语言上下文
const LanguageContext = createContext<{
  currentLanguage: string
  changeLanguage: (languageCode: string) => void
  getCurrentLanguage: () => Language
  supportedLanguages: Language[]
  t: Translation
} | null>(null)

// 语言提供者组件
export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentLanguage, setCurrentLanguage] = useState<string>('zh-CN')
  const [translation, setTranslation] = useState<Translation>(getTranslation('zh-CN'))

  useEffect(() => {
    // 从 localStorage 读取保存的语言设置
    const savedLanguage = localStorage.getItem('withssl-language')
    if (savedLanguage && supportedLanguages.find(lang => lang.code === savedLanguage)) {
      setCurrentLanguage(savedLanguage)
      setTranslation(getTranslation(savedLanguage))
    } else {
      // 检测浏览器语言
      const browserLanguage = navigator.language
      const matchedLanguage = supportedLanguages.find(lang => 
        browserLanguage.startsWith(lang.code.split('-')[0])
      )
      if (matchedLanguage) {
        setCurrentLanguage(matchedLanguage.code)
        setTranslation(getTranslation(matchedLanguage.code))
      }
    }
  }, [])

  const changeLanguage = (languageCode: string) => {
    setCurrentLanguage(languageCode)
    setTranslation(getTranslation(languageCode))
    localStorage.setItem('withssl-language', languageCode)
    
    // 触发全局重新渲染
    window.dispatchEvent(new CustomEvent('languageChanged', { 
      detail: { language: languageCode } 
    }))
  }

  const getCurrentLanguage = () => {
    return supportedLanguages.find(lang => lang.code === currentLanguage) || supportedLanguages[0]
  }

  const contextValue = {
    currentLanguage,
    changeLanguage,
    getCurrentLanguage,
    supportedLanguages,
    t: translation,
  }
  
  return React.createElement(
    LanguageContext.Provider,
    { value: contextValue },
    children
  )
}

// 使用语言上下文的 Hook
export const useLanguage = () => {
  const context = useContext(LanguageContext)
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider')
  }
  return context
}

// 使用翻译的 Hook
export const useTranslation = () => {
  const context = useContext(LanguageContext)
  if (!context) {
    throw new Error('useTranslation must be used within a LanguageProvider')
  }
  return context.t
}
