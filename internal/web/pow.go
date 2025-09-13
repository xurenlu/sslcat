package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// PowSession 保存一次 PoW 挑战信息
type PowSession struct {
	Nonce      string
	Bits       int
	CreatedAt  time.Time
	IP         string
}

// PowManager 负责发放与校验 PoW
type PowManager struct {
	sessions map[string]PowSession
	mu       sync.Mutex
	// 全局默认参数
	defaultBits int
	ttl         time.Duration
}

func NewPowManager() *PowManager {
	pm := &PowManager{
		sessions:   make(map[string]PowSession),
		defaultBits: 16,                 // 约 2^16 次尝试，客户端 ~50-150ms（更快）
		ttl:         2 * time.Minute,     // PoW 有效期
	}
	// 清理过期
	go pm.gcLoop()
	return pm
}

// Issue 生成新的 PoW 挑战
func (pm *PowManager) Issue(ip string) (nonce string, bits int) {
	// 生成 16 字节随机数作为 nonce
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce = hex.EncodeToString(b)
	bits = pm.defaultBits
	pm.mu.Lock()
	pm.sessions[nonce] = PowSession{Nonce: nonce, Bits: bits, CreatedAt: time.Now(), IP: ip}
	pm.mu.Unlock()
	return
}

// Verify 校验客户端提交的解。solution 为任意字符串，校验 sha256(nonce+":"+solution) 前导零比特数 ≥ bits
func (pm *PowManager) Verify(nonce, solution string) bool {
	if nonce == "" || solution == "" {
		return false
	}
	pm.mu.Lock()
	sess, ok := pm.sessions[nonce]
	if ok {
		delete(pm.sessions, nonce) // 一次性使用
	}
	pm.mu.Unlock()
	if !ok {
		return false
	}
	if time.Since(sess.CreatedAt) > pm.ttl {
		return false
	}
	// 计算哈希
	h := sha256.Sum256([]byte(sess.Nonce + ":" + solution))
	if leadingZeroBits(h[:]) >= sess.Bits {
		return true
	}
	return false
}

func (pm *PowManager) gcLoop() {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for range t.C {
		pm.mu.Lock()
		for k, v := range pm.sessions {
			if time.Since(v.CreatedAt) > pm.ttl {
				delete(pm.sessions, k)
			}
		}
		pm.mu.Unlock()
	}
}

// leadingZeroBits 统计字节切片的前导零比特数
func leadingZeroBits(b []byte) int {
	count := 0
	for _, by := range b {
		if by == 0 {
			count += 8
			continue
		}
		// 找到首个非零字节，统计其前导零位
		for i := 7; i >= 0; i-- {
			if (by>>uint(i))&1 == 0 {
				count++
			} else {
				return count
			}
		}
	}
	return count
}


