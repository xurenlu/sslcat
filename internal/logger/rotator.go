package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Rotator 是一个简单的按大小轮转文件写入器
// 默认通过重命名为 filename.YYYYMMDD-HHMMSS 的方式进行滚动，并保留最近 MaxFiles 个文件
type Rotator struct {
	Path     string
	MaxSize  int64
	MaxFiles int
	mu       sync.Mutex
	file     *os.File
	curSize  int64
}

// NewRotator 创建一个新的轮转写入器
func NewRotator(path string, maxSize int64, maxFiles int) (*Rotator, error) {
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB
	}
	if maxFiles <= 0 {
		maxFiles = 7
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	rot := &Rotator{Path: path, MaxSize: maxSize, MaxFiles: maxFiles}
	if err := rot.open(); err != nil {
		return nil, err
	}
	return rot, nil
}

func (r *Rotator) open() error {
	file, err := os.OpenFile(r.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	r.file = file
	if st, err := file.Stat(); err == nil {
		r.curSize = st.Size()
	}
	return nil
}

// Write 实现 io.Writer 接口
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}

	// 如果写入后超过阈值则先轮转
	if r.curSize+int64(len(p)) > r.MaxSize {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := r.file.Write(p)
	if n > 0 {
		r.curSize += int64(n)
	}
	return n, err
}

// Close 关闭当前文件
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

func (r *Rotator) rotateLocked() error {
	if r.file != nil {
		_ = r.file.Close()
	}
	// 重命名现有文件
	ts := time.Now().Format("20060102-150405")
	rotated := fmt.Sprintf("%s.%s", r.Path, ts)
	_ = os.Rename(r.Path, rotated)

	// 清理旧文件
	r.cleanupOld()

	// 重新打开
	r.curSize = 0
	return r.open()
}

func (r *Rotator) cleanupOld() {
	dir := filepath.Dir(r.Path)
	base := filepath.Base(r.Path)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var files []string
	for _, e := range ents {
		name := e.Name()
		if len(name) > len(base)+1 && name[:len(base)+1] == base+"." {
			files = append(files, filepath.Join(dir, name))
		}
	}
	if len(files) <= r.MaxFiles {
		return
	}
	// 按修改时间排序（新->旧）
	sort.Slice(files, func(i, j int) bool {
		si, _ := os.Stat(files[i])
		sj, _ := os.Stat(files[j])
		if si == nil || sj == nil {
			return files[i] > files[j]
		}
		return si.ModTime().After(sj.ModTime())
	})
	for i := r.MaxFiles; i < len(files); i++ {
		_ = os.Remove(files[i])
	}
}
