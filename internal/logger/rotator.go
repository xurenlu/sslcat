package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// writeRequest 表示一个写入请求
type writeRequest struct {
	data []byte
	err  chan error
	n    chan int
}

// Rotator 是一个简单的按大小轮转文件写入器
// 默认通过重命名为 filename.YYYYMMDD-HHMMSS 的方式进行滚动，并保留最近 MaxFiles 个文件
// 使用异步写入模式，避免阻塞调用方
type Rotator struct {
	Path     string
	MaxSize  int64
	MaxFiles int
	mu       sync.Mutex
	file     *os.File
	curSize  int64
	writeCh  chan writeRequest // 异步写入通道
	stopCh   chan struct{}     // 停止信号
	once     sync.Once         // 确保 stop 只执行一次
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
	rot := &Rotator{
		Path:     path,
		MaxSize:  maxSize,
		MaxFiles: maxFiles,
		writeCh:  make(chan writeRequest, 1000), // 缓冲1000条写入请求
		stopCh:   make(chan struct{}),
	}
	if err := rot.open(); err != nil {
		return nil, err
	}
	// 启动异步写入协程
	go rot.asyncWriter()
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

// asyncWriter 异步写入协程，处理所有文件I/O操作
func (r *Rotator) asyncWriter() {
	for {
		select {
		case req := <-r.writeCh:
			// 执行实际的写入操作（在单独的协程中，不会阻塞调用方）
			n, err := r.writeSync(req.data)
			// 将结果返回给调用方
			if req.err != nil {
				req.err <- err
			}
			if req.n != nil {
				req.n <- n
			}
		case <-r.stopCh:
			// 处理剩余的写入请求
			for len(r.writeCh) > 0 {
				req := <-r.writeCh
				r.writeSync(req.data)
				if req.err != nil {
					req.err <- nil
				}
				if req.n != nil {
					req.n <- 0
				}
			}
			return
		}
	}
}

// writeSync 同步写入，必须在 asyncWriter 协程中调用
func (r *Rotator) writeSync(p []byte) (int, error) {
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

// Write 实现 io.Writer 接口（异步非阻塞）
// 注意：返回值可能不准确（因为是异步的），但不会阻塞调用方
func (r *Rotator) Write(p []byte) (int, error) {
	// 复制数据，避免被修改
	data := make([]byte, len(p))
	copy(data, p)

	// 非阻塞发送到写入通道
	select {
	case r.writeCh <- writeRequest{data: data}:
		// 成功发送，假设写入成功（异步处理）
		return len(p), nil
	default:
		// 通道已满，丢弃数据（避免阻塞 TLS 握手）
		// 在高并发场景下，宁可丢日志也不能影响请求处理
		return len(p), nil
	}
}

// Close 关闭当前文件并停止异步写入协程
func (r *Rotator) Close() error {
	var err error
	r.once.Do(func() {
		// 发送停止信号
		close(r.stopCh)

		// 等待异步写入协程退出（最多等待1秒）
		done := make(chan struct{})
		go func() {
			// 等待 asyncWriter 退出
			for range r.writeCh {
			}
			close(done)
		}()

		select {
		case <-done:
			// 正常退出
		case <-time.After(1 * time.Second):
			// 超时，强制关闭
		}

		// 关闭文件
		r.mu.Lock()
		if r.file != nil {
			err = r.file.Close()
			r.file = nil
		}
		r.mu.Unlock()
	})
	return err
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
