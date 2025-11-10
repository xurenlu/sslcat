package runner

import (
	"io/fs"
	"time"
)

// TemplateSource 定义模板来源
type TemplateSource string

const (
	// TemplateSourceBuiltin 表示内置模板（编译时嵌入）
	TemplateSourceBuiltin TemplateSource = "builtin"
	// TemplateSourceCustom 表示用户自定义模板（data/templates）
	TemplateSourceCustom TemplateSource = "custom"
)

// TemplateMeta 描述模板元数据
type TemplateMeta struct {
	ID                string                 `yaml:"id" json:"id"`
	Name              string                 `yaml:"name" json:"name"`
	Category          string                 `yaml:"category" json:"category"`
	Subcategory       string                 `yaml:"subcategory,omitempty" json:"subcategory,omitempty"`
	Tags              []string               `yaml:"tags,omitempty" json:"tags,omitempty"`
	Description       string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Icon              string                 `yaml:"icon,omitempty" json:"icon,omitempty"`
	Version           string                 `yaml:"version,omitempty" json:"version,omitempty"`
	Author            string                 `yaml:"author,omitempty" json:"author,omitempty"`
	Website           string                 `yaml:"website,omitempty" json:"website,omitempty"`
	ComposeFile       string                 `yaml:"compose_file,omitempty" json:"compose_file,omitempty"`
	Variables         []TemplateVariable     `yaml:"variables,omitempty" json:"variables,omitempty"`
	Services          []TemplateService      `yaml:"services,omitempty" json:"services,omitempty"`
	Credentials       TemplateCredentialSpec `yaml:"credentials,omitempty" json:"credentials,omitempty"`
	ConnectionStrings map[string]string      `yaml:"connection_strings,omitempty" json:"connection_strings,omitempty"`
	Healthcheck       TemplateHealthcheck    `yaml:"healthcheck_global,omitempty" json:"healthcheck_global,omitempty"`
	Links             map[string]string      `yaml:"links,omitempty" json:"links,omitempty"`
	Metadata          map[string]string      `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// TemplateVariable 定义模板变量
type TemplateVariable struct {
	Name         string        `yaml:"name" json:"name"`
	Type         string        `yaml:"type" json:"type"`
	Title        string        `yaml:"title,omitempty" json:"title,omitempty"`
	Description  string        `yaml:"description,omitempty" json:"description,omitempty"`
	Required     bool          `yaml:"required,omitempty" json:"required,omitempty"`
	Default      interface{}   `yaml:"default,omitempty" json:"default,omitempty"`
	Placeholder  string        `yaml:"placeholder,omitempty" json:"placeholder,omitempty"`
	Options      []interface{} `yaml:"options,omitempty" json:"options,omitempty"`
	Min          *float64      `yaml:"min,omitempty" json:"min,omitempty"`
	Max          *float64      `yaml:"max,omitempty" json:"max,omitempty"`
	Pattern      string        `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Example      string        `yaml:"example,omitempty" json:"example,omitempty"`
	Sensitive    bool          `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	Group        string        `yaml:"group,omitempty" json:"group,omitempty"`
	Advanced     bool          `yaml:"advanced,omitempty" json:"advanced,omitempty"`
	Dependencies []string      `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
}

// TemplateService 描述模板中的单个服务
type TemplateService struct {
	Name        string                       `yaml:"name" json:"name"`
	Type        string                       `yaml:"type,omitempty" json:"type,omitempty"`
	Description string                       `yaml:"description,omitempty" json:"description,omitempty"`
	Optional    bool                         `yaml:"optional,omitempty" json:"optional,omitempty"`
	DependsOn   []string                     `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Ports       []TemplatePort               `yaml:"ports,omitempty" json:"ports,omitempty"`
	Volumes     []TemplateVolume             `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	Environment TemplateServiceEnvironment   `yaml:"env,omitempty" json:"env,omitempty"`
	Healthcheck TemplateHealthcheck          `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
	Labels      map[string]string            `yaml:"labels,omitempty" json:"labels,omitempty"`
	Resources   TemplateServiceResourceHints `yaml:"resources,omitempty" json:"resources,omitempty"`
	Command     []string                     `yaml:"command,omitempty" json:"command,omitempty"`
	Entrypoint  []string                     `yaml:"entrypoint,omitempty" json:"entrypoint,omitempty"`
}

// TemplateServiceResourceHints 提供资源提示
type TemplateServiceResourceHints struct {
	CPU      string `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory   string `yaml:"memory,omitempty" json:"memory,omitempty"`
	Storage  string `yaml:"storage,omitempty" json:"storage,omitempty"`
	GPU      string `yaml:"gpu,omitempty" json:"gpu,omitempty"`
	Replicas int    `yaml:"replicas,omitempty" json:"replicas,omitempty"`
}

// TemplatePort 描述端口映射
type TemplatePort struct {
	Internal int    `yaml:"internal" json:"internal"`
	External *int   `yaml:"external,omitempty" json:"external,omitempty"`
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Public   bool   `yaml:"public,omitempty" json:"public,omitempty"`
}

// TemplateVolume 描述卷映射
type TemplateVolume struct {
	Name string `yaml:"name" json:"name"`
	Path string `yaml:"path" json:"path"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// TemplateServiceEnvironment 描述环境变量需求
type TemplateServiceEnvironment struct {
	Required []string          `yaml:"required,omitempty" json:"required,omitempty"`
	Optional []string          `yaml:"optional,omitempty" json:"optional,omitempty"`
	Defaults map[string]string `yaml:"defaults,omitempty" json:"defaults,omitempty"`
}

// TemplateHealthcheck 描述健康检查
type TemplateHealthcheck struct {
	Type        string            `yaml:"type,omitempty" json:"type,omitempty"`
	Command     []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Path        string            `yaml:"path,omitempty" json:"path,omitempty"`
	Port        int               `yaml:"port,omitempty" json:"port,omitempty"`
	Interval    time.Duration     `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout     time.Duration     `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries     int               `yaml:"retries,omitempty" json:"retries,omitempty"`
	StartPeriod time.Duration     `yaml:"start_period,omitempty" json:"start_period,omitempty"`
	Header      map[string]string `yaml:"header,omitempty" json:"header,omitempty"`
}

// TemplateCredentialSpec 描述凭证需求
type TemplateCredentialSpec map[string]TemplateCredentialRule

// TemplateCredentialRule 描述某服务的凭证生成规则
type TemplateCredentialRule struct {
	Username TemplateCredentialPattern `yaml:"username,omitempty" json:"username,omitempty"`
	Password TemplateCredentialPattern `yaml:"password,omitempty" json:"password,omitempty"`
	Database TemplateCredentialPattern `yaml:"database,omitempty" json:"database,omitempty"`
	Token    TemplateCredentialPattern `yaml:"token,omitempty" json:"token,omitempty"`
	Secret   TemplateCredentialPattern `yaml:"secret,omitempty" json:"secret,omitempty"`
	Endpoint TemplateCredentialPattern `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
}

// TemplateCredentialPattern 描述凭证生成模式
type TemplateCredentialPattern struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Length  int    `yaml:"length,omitempty" json:"length,omitempty"`
	Charset string `yaml:"charset,omitempty" json:"charset,omitempty"`
	Prefix  string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Suffix  string `yaml:"suffix,omitempty" json:"suffix,omitempty"`
}

// AppTemplate 代表加载后的模板
type AppTemplate struct {
	Meta         TemplateMeta   `json:"meta"`
	Source       TemplateSource `json:"source"`
	RootFS       fs.FS          `json:"-"`
	RootPath     string         `json:"root_path,omitempty"`
	ComposePath  string         `json:"compose_path"`
	Readme       string         `json:"readme,omitempty"`
	Assets       []string       `json:"assets,omitempty"`
	LastModified time.Time      `json:"last_modified"`
}
