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

export const useFormValidation = <T extends Record<string, any>>(
  initialValues: T,
  validationRules: ValidationRules
) => {
  const [values, setValues] = useState<T>(initialValues)
  const [errors, setErrors] = useState<ValidationErrors>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})

  const validateField = useCallback((field: string, value: any): string | null => {
    const rules = validationRules[field]
    if (!rules) return null

    // Required validation
    if (rules.required && (!value || value.toString().trim() === '')) {
      return '此字段为必填项'
    }

    // Skip other validations if field is empty and not required
    if (!value || value.toString().trim() === '') {
      return null
    }

    // Min length validation
    if (rules.minLength && value.toString().length < rules.minLength) {
      return `最少需要 ${rules.minLength} 个字符`
    }

    // Max length validation
    if (rules.maxLength && value.toString().length > rules.maxLength) {
      return `最多允许 ${rules.maxLength} 个字符`
    }

    // Pattern validation
    if (rules.pattern && !rules.pattern.test(value.toString())) {
      return '格式不正确'
    }

    // Custom validation
    if (rules.custom) {
      return rules.custom(value)
    }

    return null
  }, [validationRules])

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
  port: {
    pattern: /^\d+$/,
    custom: (value: string) => {
      const port = parseInt(value)
      if (port < 1 || port > 65535) {
        return '端口号必须在 1-65535 之间'
      }
      return null
    },
  },
  ip: {
    pattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  },
}
