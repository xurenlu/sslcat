package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SessionStorage 会话存储接口
type SessionStorage interface {
	Set(key string, session *Session) error
	Get(key string) (*Session, error)
	Delete(key string) error
	GetAll() (map[string]*Session, error)
	Close() error
}

// FileSessionStorage 文件会话存储实现
type FileSessionStorage struct {
	dataDir  string
	mutex    sync.RWMutex
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewFileSessionStorage 创建文件会话存储
func NewFileSessionStorage(dataDir string) (*FileSessionStorage, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}

	storage := &FileSessionStorage{
		dataDir:  dataDir,
		stopChan: make(chan struct{}),
	}

	// 启动过期清理goroutine
	storage.wg.Add(1)
	go func() {
		defer storage.wg.Done()
		storage.cleanupExpiredSessions()
	}()

	return storage, nil
}

// Set 设置会话
func (s *FileSessionStorage) Set(key string, session *Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("序列化会话失败: %v", err)
	}

	filePath, err := s.sessionPath(key)
	if err != nil {
		return err
	}
	return writeSensitiveFileAtomically(filePath, data, 0600)
}

// Get 获取会话
func (s *FileSessionStorage) Get(key string) (*Session, error) {
	filePath, err := s.sessionPath(key)
	if err != nil {
		return nil, err
	}

	s.mutex.RLock()
	data, err := os.ReadFile(filePath)
	s.mutex.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("读取会话文件失败: %v", err)
	}

	session := &Session{}
	if err := json.Unmarshal(data, session); err != nil {
		return nil, fmt.Errorf("反序列化会话失败: %v", err)
	}

	// 检查是否过期
	if time.Now().After(session.ExpiresAt) {
		_ = s.Delete(key)
		return nil, fmt.Errorf("会话已过期")
	}

	return session, nil
}

// Delete 删除会话
func (s *FileSessionStorage) Delete(key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	filePath, err := s.sessionPath(key)
	if err != nil {
		return err
	}
	return os.Remove(filePath)
}

// GetAll 获取所有会话
func (s *FileSessionStorage) GetAll() (map[string]*Session, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sessions := make(map[string]*Session)

	files, err := filepath.Glob(filepath.Join(s.dataDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("读取会话文件列表失败: %v", err)
	}

	now := time.Now()
	for _, file := range files {
		key := filepath.Base(file[:len(file)-5]) // 移除.json扩展名

		data, err := os.ReadFile(file)
		if err != nil {
			continue // 跳过无法读取的文件
		}

		session := &Session{}
		if err := json.Unmarshal(data, session); err != nil {
			continue // 跳过无法解析的文件
		}

		// 只返回未过期的会话
		if now.Before(session.ExpiresAt) {
			sessions[key] = session
		}
	}

	return sessions, nil
}

// Close 关闭存储
func (s *FileSessionStorage) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopChan)
	})
	s.wg.Wait()
	return nil
}

// cleanupExpiredSessions 清理过期会话
func (s *FileSessionStorage) cleanupExpiredSessions() {
	ticker := time.NewTicker(13 * time.Minute) // 使用质数间隔避免与其他定时器同时触发
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mutex.Lock()
			files, err := filepath.Glob(filepath.Join(s.dataDir, "*.json"))
			if err == nil {
				now := time.Now()
				for _, file := range files {
					data, err := os.ReadFile(file)
					if err != nil {
						continue
					}

					session := &Session{}
					if err := json.Unmarshal(data, session); err != nil {
						continue
					}

					// 删除过期会话文件
					if now.After(session.ExpiresAt) {
						os.Remove(file)
					}
				}
			}
			s.mutex.Unlock()
		case <-s.stopChan:
			return
		}
	}
}

func (s *FileSessionStorage) sessionPath(key string) (string, error) {
	if key == "" || filepath.Base(key) != key || strings.Contains(key, `\`) || strings.Contains(key, "..") {
		return "", fmt.Errorf("无效会话键")
	}
	return filepath.Join(s.dataDir, key+".json"), nil
}

// MemorySessionStorage 内存会话存储（原有实现）
type MemorySessionStorage struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

// NewMemorySessionStorage 创建内存会话存储
func NewMemorySessionStorage() *MemorySessionStorage {
	return &MemorySessionStorage{
		sessions: make(map[string]*Session),
	}
}

func (m *MemorySessionStorage) Set(key string, session *Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sessions[key] = session
	return nil
}

func (m *MemorySessionStorage) Get(key string) (*Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	session, exists := m.sessions[key]
	if !exists {
		return nil, fmt.Errorf("会话不存在")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(m.sessions, key)
		return nil, fmt.Errorf("会话已过期")
	}

	return session, nil
}

func (m *MemorySessionStorage) Delete(key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.sessions, key)
	return nil
}

func (m *MemorySessionStorage) GetAll() (map[string]*Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	result := make(map[string]*Session)
	now := time.Now()

	for key, session := range m.sessions {
		if now.Before(session.ExpiresAt) {
			result[key] = session
		}
	}

	return result, nil
}

func (m *MemorySessionStorage) Close() error {
	return nil
}
