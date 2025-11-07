package runner

import "embed"

// builtinTemplateFS 内置模板文件系统（编译时嵌入）
//
//go:embed templates/builtin/**
var builtinTemplateFS embed.FS


