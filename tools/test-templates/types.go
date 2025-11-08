package main

import (
	"time"
)

// TestStatus 测试状态
type TestStatus string

const (
	StatusPending TestStatus = "pending"
	StatusRunning TestStatus = "running"
	StatusPassed  TestStatus = "passed"
	StatusFailed  TestStatus = "failed"
	StatusSkipped TestStatus = "skipped"
)

// StageStatus 阶段状态
type StageStatus struct {
	Status   TestStatus `json:"status"`
	Duration string     `json:"duration"`
	Error    string    `json:"error,omitempty"`
	Message  string    `json:"message,omitempty"`
}

// TestResult 单个模板的测试结果
type TestResult struct {
	TemplateID   string                 `json:"template_id"`
	TemplateName string                 `json:"template_name"`
	Category     string                 `json:"category"`
	Subcategory  string                 `json:"subcategory,omitempty"`
	Priority     string                 `json:"priority,omitempty"` // high/medium/low
	Status       TestStatus             `json:"status"`
	Stages       map[string]StageStatus `json:"stages"`
	Errors       []string               `json:"errors"`
	Warnings     []string               `json:"warnings"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Duration     string                 `json:"duration"`
	ImageNames   []string               `json:"image_names,omitempty"` // 使用的镜像名称
}

// TestSummary 测试汇总
type TestSummary struct {
	Total    int    `json:"total"`
	Passed   int    `json:"passed"`
	Failed   int    `json:"failed"`
	Skipped  int    `json:"skipped"`
	Duration string `json:"duration"`
}

// TestReport 完整的测试报告
type TestReport struct {
	Summary TestSummary  `json:"summary"`
	Results []TestResult `json:"results"`
}

// TemplateInfo 模板信息
type TemplateInfo struct {
	ID          string
	Name        string
	Category    string
	Subcategory string
	Dir         string
	ComposeFile string
	MetaPath    string
}

// ComposeService Docker Compose 服务定义
type ComposeService struct {
	Image       string                 `yaml:"image"`
	Ports       []string               `yaml:"ports,omitempty"`
	Environment map[string]interface{} `yaml:"environment,omitempty"`
	Volumes     []string               `yaml:"volumes,omitempty"`
	DependsOn   []string               `yaml:"depends_on,omitempty"`
	Healthcheck map[string]interface{} `yaml:"healthcheck,omitempty"`
}

// ComposeFile Docker Compose 文件结构
type ComposeFile struct {
	Version  string                    `yaml:"version"`
	Services map[string]ComposeService `yaml:"services"`
	Volumes  map[string]interface{}    `yaml:"volumes,omitempty"`
	Networks map[string]interface{}    `yaml:"networks,omitempty"`
}

// TemplateMeta 模板元数据（简化版）
type TemplateMeta struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Category    string            `yaml:"category"`
	Subcategory string            `yaml:"subcategory,omitempty"`
	Variables   []TemplateVar     `yaml:"variables,omitempty"`
	Services    []TemplateService `yaml:"services,omitempty"`
	Healthcheck TemplateHealthcheck `yaml:"healthcheck_global,omitempty"`
}

// TemplateHealthcheck 健康检查配置
type TemplateHealthcheck struct {
	Timeout time.Duration `yaml:"timeout,omitempty"`
	Interval time.Duration `yaml:"interval,omitempty"`
}

// TemplateVar 模板变量
type TemplateVar struct {
	Name    string      `yaml:"name"`
	Type    string      `yaml:"type"`
	Default interface{} `yaml:"default,omitempty"`
	Options []interface{} `yaml:"options,omitempty"`
}

// TemplateService 模板服务定义
type TemplateService struct {
	Name  string       `yaml:"name"`
	Ports []PortConfig `yaml:"ports,omitempty"`
}

// PortConfig 端口配置
type PortConfig struct {
	Internal int    `yaml:"internal"`
	External *int   `yaml:"external,omitempty"`
	Public   bool   `yaml:"public,omitempty"`
	Protocol string `yaml:"protocol,omitempty"`
}

