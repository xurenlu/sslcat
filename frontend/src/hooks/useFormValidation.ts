import { useState, useCallback } from 'react'

interface ValidationRule {
  required?: boolean
  minLength?: number
  maxLength?: number
  pattern?: RegExp
  custom?: (value: any) => string | null
}

interface ValidationRules {
  [field: string]: ValidationRule
}

interface ValidationErrors {
  [field: string]: string
}

export interface TranslationHelper {
  fieldRequired: string
  minLengthError: (n: number) => string
  maxLengthError: (n: number) => string
  invalidFormat: string
  portRangeError: string
}

// 默认翻译（中文，向后兼容）
const defaultTranslation: TranslationHelper = {
  fieldRequired: '此字段为必填项',
  minLengthError: (n: number) => `最少需要 ${n} 个字符`,
  maxLengthError: (n: number) => `最多允许 ${n} 个字符`,
  invalidFormat: '格式不正确',
  portRangeError: '端口号必须在 1-65535 之间',
}

// 从翻译对象创建 TranslationHelper 的辅助函数
export const createTranslationHelper = (t: {
  fieldRequired: string
  minLengthError: string
  maxLengthError: string
  invalidFormat: string
  portRangeError: string
}): TranslationHelper => ({
  fieldRequired: t.fieldRequired,
  minLengthError: (n: number) => t.minLengthError.replace('{n}', String(n)),
  maxLengthError: (n: number) => t.maxLengthError.replace('{n}', String(n)),
  invalidFormat: t.invalidFormat,
  portRangeError: t.portRangeError,
})

export const useFormValidation = <T extends Record<string, any>>(
  initialValues: T,
  validationRules: ValidationRules,
  translation?: TranslationHelper
) => {
  const [values, setValues] = useState<T>(initialValues)
  const [errors, setErrors] = useState<ValidationErrors>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const t = translation || defaultTranslation

  const validateField = useCallback((field: string, value: any): string | null => {
    const rules = validationRules[field]
    if (!rules) return null

    // Required validation
    if (rules.required && (!value || value.toString().trim() === '')) {
      return t.fieldRequired
    }

    // Skip other validations if field is empty and not required
    if (!value || value.toString().trim() === '') {
      return null
    }

    // Min length validation
    if (rules.minLength && value.toString().length < rules.minLength) {
      return t.minLengthError(rules.minLength)
    }

    // Max length validation
    if (rules.maxLength && value.toString().length > rules.maxLength) {
      return t.maxLengthError(rules.maxLength)
    }

    // Pattern validation
    if (rules.pattern && !rules.pattern.test(value.toString())) {
      return t.invalidFormat
    }

    // Custom validation
    if (rules.custom) {
      return rules.custom(value)
    }

    return null
  }, [validationRules, t])

  const validateAllFields = useCallback((): boolean => {
    const newErrors: ValidationErrors = {}
    let hasErrors = false

    Object.keys(validationRules).forEach(field => {
      const error = validateField(field, values[field])
      if (error) {
        newErrors[field] = error
        hasErrors = true
      }
    })

    setErrors(newErrors)
    return !hasErrors
  }, [values, validateField, validationRules])

  const setValue = useCallback((field: string, value: any) => {
    setValues(prev => ({ ...prev, [field]: value }))
    
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }))
    }
  }, [errors])

  const setFieldTouched = useCallback((field: string) => {
    setTouched(prev => ({ ...prev, [field]: true }))
    
    // Validate field when it loses focus
    const error = validateField(field, values[field])
    if (error) {
      setErrors(prev => ({ ...prev, [field]: error }))
    }
  }, [values, validateField])

  const resetForm = useCallback(() => {
    setValues(initialValues)
    setErrors({})
    setTouched({})
  }, [initialValues])

  const getFieldProps = useCallback((field: string) => ({
    value: values[field] || '',
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
      setValue(field, e.target.value)
    },
    onBlur: () => setFieldTouched(field),
    isInvalid: touched[field] && !!errors[field],
  }), [values, errors, touched, setValue, setFieldTouched])

  const getFieldError = useCallback((field: string) => {
    return touched[field] ? errors[field] : undefined
  }, [errors, touched])

  return {
    values,
    errors,
    touched,
    setValue,
    setFieldTouched,
    validateAllFields,
    resetForm,
    getFieldProps,
    getFieldError,
    isValid: Object.keys(errors).length === 0,
  }
}

// Common validation rules
export const validationRules = {
  required: { required: true },
  email: {
    required: true,
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  },
  domain: {
    required: true,
    pattern: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  },
  url: {
    pattern: /^https?:\/\/.+/,
  },
  port: (translation?: TranslationHelper) => ({
    pattern: /^\d+$/,
    custom: (value: string) => {
      const port = parseInt(value)
      if (port < 1 || port > 65535) {
        return (translation || defaultTranslation).portRangeError
      }
      return null
    },
  }),
  ip: {
    pattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  },
}
