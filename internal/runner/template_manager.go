package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// TemplateManager 负责加载与管理部署模板
type TemplateManager struct {
	logger    *logrus.Entry
	customDir string

	builtinTemplates map[string]*AppTemplate
	customTemplates  map[string]*AppTemplate
	combined         map[string]*AppTemplate

	watcher   *fsnotify.Watcher
	watchOnce sync.Once
	watchMu   sync.Mutex

	mutex sync.RWMutex
}

// NewTemplateManager 创建模板管理器
func NewTemplateManager(logger *logrus.Logger, dataDir string) *TemplateManager {
	customDir := ""
	if dataDir != "" {
		customDir = filepath.Join(dataDir, "templates")
	}

	entry := logger.WithField("component", "template_manager")

	return &TemplateManager{
		logger:           entry,
		customDir:        customDir,
		builtinTemplates: make(map[string]*AppTemplate),
		customTemplates:  make(map[string]*AppTemplate),
		combined:         make(map[string]*AppTemplate),
	}
}

// LoadAll 加载内置和自定义模板
func (tm *TemplateManager) LoadAll() error {
	if err := tm.loadBuiltinTemplates(); err != nil {
		return err
	}

	if err := tm.loadCustomTemplates(); err != nil {
		return err
	}

	tm.refreshCombined()
	return nil
}

// Watch 启动自定义模板目录的热更新监控
func (tm *TemplateManager) Watch(ctx context.Context) error {
	if tm.customDir == "" {
		return nil
	}

	if err := os.MkdirAll(tm.customDir, 0o755); err != nil {
		return fmt.Errorf("创建模板目录失败: %w", err)
	}

	var err error
	tm.watchOnce.Do(func() {
		var watcher *fsnotify.Watcher
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return
		}
		tm.watchMu.Lock()
		tm.watcher = watcher
		tm.watchMu.Unlock()

		go tm.watchLoop(ctx, watcher)
	})

	if err != nil {
		return err
	}

	tm.watchMu.Lock()
	defer tm.watchMu.Unlock()

	if tm.watcher == nil {
		return errors.New("fsnotify watcher 未初始化")
	}

	// 监听顶层目录即可，变更时重新加载
	if err := tm.watcher.Add(tm.customDir); err != nil {
		return fmt.Errorf("监听模板目录失败: %w", err)
	}

	return nil
}

// Close 释放资源
func (tm *TemplateManager) Close() error {
	tm.watchMu.Lock()
	defer tm.watchMu.Unlock()

	if tm.watcher != nil {
		err := tm.watcher.Close()
		tm.watcher = nil
		return err
	}

	return nil
}

// List 列出所有模板（按名称排序）
func (tm *TemplateManager) List() []*AppTemplate {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	result := make([]*AppTemplate, 0, len(tm.combined))
	for _, tpl := range tm.combined {
		result = append(result, tpl)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Meta.Category == result[j].Meta.Category {
			return strings.ToLower(result[i].Meta.Name) < strings.ToLower(result[j].Meta.Name)
		}
		return strings.ToLower(result[i].Meta.Category) < strings.ToLower(result[j].Meta.Category)
	})

	return result
}

// Get 根据模板 ID 获取模板
func (tm *TemplateManager) Get(id string) (*AppTemplate, bool) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	tpl, ok := tm.combined[id]
	return tpl, ok
}

// Count 返回模板数量
func (tm *TemplateManager) Count() int {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	return len(tm.combined)
}

func (tm *TemplateManager) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) {
	for {
		select {
		case <-ctx.Done():
			tm.logger.Info("停止模板目录监听")
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			tm.logger.WithField("event", event).Debug("检测到模板目录变更，重新加载自定义模板")
			if err := tm.loadCustomTemplates(); err != nil {
				tm.logger.WithError(err).Error("重新加载自定义模板失败")
				continue
			}
			tm.refreshCombined()
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			tm.logger.WithError(err).Warn("模板目录监听发生错误")
		}
	}
}

func (tm *TemplateManager) loadBuiltinTemplates() error {
	subFS, err := fs.Sub(builtinTemplateFS, "templates/builtin")
	if err != nil {
		// 若目录不存在，视为无内置模板
		if errors.Is(err, fs.ErrNotExist) {
			tm.logger.Warn("未找到内置模板目录，跳过加载")
			return nil
		}
		return fmt.Errorf("访问内置模板失败: %w", err)
	}

	tpls, err := tm.loadTemplatesFromFS(subFS, TemplateSourceBuiltin, "")
	if err != nil {
		return err
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.builtinTemplates = tpls
	return nil
}

func (tm *TemplateManager) loadCustomTemplates() error {
	if tm.customDir == "" {
		return nil
	}

	if err := os.MkdirAll(tm.customDir, 0o755); err != nil {
		return fmt.Errorf("创建模板目录失败: %w", err)
	}

	fsys := os.DirFS(tm.customDir)
	tpls, err := tm.loadTemplatesFromFS(fsys, TemplateSourceCustom, tm.customDir)
	if err != nil {
		return err
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.customTemplates = tpls
	return nil
}

func (tm *TemplateManager) refreshCombined() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	combined := make(map[string]*AppTemplate, len(tm.builtinTemplates)+len(tm.customTemplates))

	for id, tpl := range tm.builtinTemplates {
		combined[id] = tpl
	}

	for id, tpl := range tm.customTemplates {
		combined[id] = tpl
	}

	tm.combined = combined
	tm.logger.WithFields(logrus.Fields{
		"builtin": len(tm.builtinTemplates),
		"custom":  len(tm.customTemplates),
		"total":   len(tm.combined),
	}).Info("模板加载完成")
}

func (tm *TemplateManager) loadTemplatesFromFS(fsys fs.FS, source TemplateSource, rootPath string) (map[string]*AppTemplate, error) {
	templates := make(map[string]*AppTemplate)

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() {
			return nil
		}

		if !strings.EqualFold(filepath.Base(path), "template.yaml") {
			return nil
		}

		tpl, err := tm.readTemplate(fsys, filepath.Dir(path), source, rootPath)
		if err != nil {
			return err
		}

		if tpl == nil {
			return nil
		}

		templates[tpl.Meta.ID] = tpl
		return nil
	}

	if err := fs.WalkDir(fsys, ".", walkFn); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return templates, nil
		}
		return nil, err
	}

	return templates, nil
}

func (tm *TemplateManager) readTemplate(fsys fs.FS, dir string, source TemplateSource, rootPath string) (*AppTemplate, error) {
	metaPath := filepath.Join(dir, "template.yaml")
	metaBytes, err := fs.ReadFile(fsys, metaPath)
	if err != nil {
		return nil, fmt.Errorf("读取模板元数据失败: %w", err)
	}

	var meta TemplateMeta
	if err := yaml.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("解析模板元数据失败: %w", err)
	}

	meta.ID = strings.TrimSpace(meta.ID)
	if meta.ID == "" {
		return nil, errors.New("模板 ID 不能为空")
	}

	if meta.ComposeFile == "" {
		meta.ComposeFile = "docker-compose.yml"
	}

	composeRel := filepath.Join(dir, meta.ComposeFile)
	if _, err := fs.Stat(fsys, composeRel); err != nil {
		return nil, fmt.Errorf("模板 %s 缺少 compose 文件 %s: %w", meta.ID, meta.ComposeFile, err)
	}

	readmeRel := filepath.Join(dir, "README.md")
	readme := ""
	if b, err := fs.ReadFile(fsys, readmeRel); err == nil {
		readme = string(b)
	}

	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("创建模板子文件系统失败: %w", err)
	}

	pl := &AppTemplate{
		Meta:        meta,
		Source:      source,
		RootFS:      sub,
		ComposePath: meta.ComposeFile,
		Readme:      readme,
		Assets:      tm.collectAssets(sub),
	}

	if source == TemplateSourceCustom {
		absPath := rootPath
		if absPath != "" {
			absPath = filepath.Join(rootPath, dir)
		}
		if absPath == "" {
			absPath = dir
		}
		pl.RootPath = absPath
		if info, err := os.Stat(absPath); err == nil {
			pl.LastModified = info.ModTime()
		}
	} else {
		pl.LastModified = time.Now().UTC()
	}

	return pl, nil
}

func (tm *TemplateManager) collectAssets(fsys fs.FS) []string {
	assets := []string{}
	_ = fs.WalkDir(fsys, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		assets = append(assets, path)
		return nil
	})
	return assets
}
