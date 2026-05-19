package ssl

import "sync"

type certRequestLock struct {
	mu   sync.Mutex
	refs int
}

// CreateProgressChannel 为域名创建进度通道。若已有同域名通道，返回现有通道，避免覆盖正在使用的通道。
func (m *Manager) CreateProgressChannel(domain string) chan CertProgressEvent {
	ch, _ := m.TryCreateProgressChannel(domain)
	if ch != nil {
		return ch
	}

	m.progressMutex.RLock()
	defer m.progressMutex.RUnlock()
	return m.progressChannels[domain]
}

// TryCreateProgressChannel 尝试为域名创建独占进度通道。
func (m *Manager) TryCreateProgressChannel(domain string) (chan CertProgressEvent, bool) {
	m.progressMutex.Lock()
	defer m.progressMutex.Unlock()

	if _, exists := m.progressChannels[domain]; exists {
		return nil, false
	}
	ch := make(chan CertProgressEvent, 32)
	m.progressChannels[domain] = ch
	return ch, true
}

// GetProgressChannel 获取域名的进度通道
func (m *Manager) GetProgressChannel(domain string) (chan CertProgressEvent, bool) {
	m.progressMutex.RLock()
	defer m.progressMutex.RUnlock()

	ch, ok := m.progressChannels[domain]
	return ch, ok
}

// CloseProgressChannel 关闭并删除进度通道
func (m *Manager) CloseProgressChannel(domain string) {
	m.progressMutex.Lock()
	defer m.progressMutex.Unlock()

	if ch, ok := m.progressChannels[domain]; ok {
		close(ch)
		delete(m.progressChannels, domain)
	}
}

// CloseProgressChannelIfMatch 只关闭调用方创建的通道，避免同域并发请求误关其他请求的通道。
func (m *Manager) CloseProgressChannelIfMatch(domain string, ch chan CertProgressEvent) bool {
	m.progressMutex.Lock()
	defer m.progressMutex.Unlock()

	current, ok := m.progressChannels[domain]
	if !ok || current != ch {
		return false
	}
	close(current)
	delete(m.progressChannels, domain)
	return true
}

// sendProgressEvent 发送进度事件（非阻塞）
func (m *Manager) sendProgressEvent(domain string, event CertProgressEvent) {
	m.progressMutex.RLock()
	defer m.progressMutex.RUnlock()

	ch, ok := m.progressChannels[domain]
	if !ok {
		return
	}
	select {
	case ch <- event:
	default:
		// 通道已满，跳过（避免阻塞）
	}
}

func (m *Manager) lockCertRequest(domain string) func() {
	m.certRequestMu.Lock()
	lock, ok := m.certRequestLocks[domain]
	if !ok {
		lock = &certRequestLock{}
		m.certRequestLocks[domain] = lock
	}
	lock.refs++
	m.certRequestMu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()

		m.certRequestMu.Lock()
		defer m.certRequestMu.Unlock()

		lock.refs--
		if lock.refs == 0 && m.certRequestLocks[domain] == lock {
			delete(m.certRequestLocks, domain)
		}
	}
}
