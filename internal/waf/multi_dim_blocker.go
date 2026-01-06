package waf

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// BlockDimension 封禁维度
type BlockDimension string

const (
	DimensionIP     BlockDimension = "ip"
	DimensionTLS    BlockDimension = "tls_fingerprint"
	DimensionSubnet BlockDimension = "ip_subnet"
)

// BlockRecord 封禁记录
type BlockRecord struct {
	Dimension  BlockDimension `json:"dimension"`
	Value      string         `json:"value"`       // IP/TLS指纹/IP段
	Reason     string         `json:"reason"`      // 封禁原因
	ExpireTime time.Time      `json:"expire_time"` // 到期时间
	HitCount   int            `json:"hit_count"`   // 触发次数
	FirstSeen  time.Time      `json:"first_seen"`  // 首次发现
	LastSeen   time.Time      `json:"last_seen"`   // 最后触发
}

// MultiDimBlockConfig 多维度封禁配置
type MultiDimBlockConfig struct {
	// IP 维度配置
	IPEnabled       bool
	IPWindow        time.Duration
	IPMaxHits       int
	IPBlockDuration time.Duration

	// TLS 指纹维度配置
	TLSEnabled       bool
	TLSWindow        time.Duration
	TLSMaxHits       int
	TLSBlockDuration time.Duration

	// IP 段维度配置
	SubnetEnabled       bool
	SubnetMask          int           // 默认 24 (/24)
	SubnetThreshold     int           // 同段被封IP数量阈值，默认 3
	SubnetBlockDuration time.Duration
}

// wafMultiDimBlocker 多维度封禁器
type wafMultiDimBlocker struct {
	mu sync.RWMutex

	// IP 维度
	ipBlocked map[string]*BlockRecord
	ipHits    map[string][]time.Time

	// TLS 指纹维度
	tlsBlocked map[string]*BlockRecord
	tlsHits    map[string][]time.Time
	tlsToIPs   map[string][]string // TLS指纹 -> IP列表

	// IP 段维度
	subnetBlocked map[string]*BlockRecord // CIDR -> BlockRecord
	subnetHits    map[string]int          // /24段 -> 被封IP数量

	// 配置
	config        *MultiDimBlockConfig
	log           *logrus.Entry
	cleanupTicker *time.Ticker
	stopChan      chan struct{}

	// 白名单检查函数（可选）
	whitelistChecker func(ip string) bool
}

// newWAFMultiDimBlocker 创建多维度封禁器
func newWAFMultiDimBlocker(config *MultiDimBlockConfig, log *logrus.Entry) *wafMultiDimBlocker {
	if config == nil {
		config = &MultiDimBlockConfig{
			IPEnabled:           false,
			IPWindow:            60 * time.Second,
			IPMaxHits:           10,
			IPBlockDuration:     3600 * time.Second,
			TLSEnabled:          false,
			TLSWindow:           60 * time.Second,
			TLSMaxHits:          10,
			TLSBlockDuration:    3600 * time.Second,
			SubnetEnabled:       false,
			SubnetMask:          24,
			SubnetThreshold:     3,
			SubnetBlockDuration: 7200 * time.Second,
		}
	}

	blocker := &wafMultiDimBlocker{
		ipBlocked:     make(map[string]*BlockRecord),
		ipHits:        make(map[string][]time.Time),
		tlsBlocked:    make(map[string]*BlockRecord),
		tlsHits:       make(map[string][]time.Time),
		tlsToIPs:      make(map[string][]string),
		subnetBlocked: make(map[string]*BlockRecord),
		subnetHits:    make(map[string]int),
		config:        config,
		log:           log,
		cleanupTicker: time.NewTicker(5 * time.Minute),
		stopChan:      make(chan struct{}),
	}

	// 启动清理协程
	go blocker.cleanup()

	return blocker
}

// RecordHit 记录触发事件
func (b *wafMultiDimBlocker) RecordHit(ip, tlsFingerprint string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	// 1. 记录 IP 触发
	if b.config.IPEnabled && ip != "" {
		b.recordIPHit(ip, now)
	}

	// 2. 记录 TLS 指纹触发
	if b.config.TLSEnabled && tlsFingerprint != "" {
		b.recordTLSHit(tlsFingerprint, ip, now)
	}

	// 3. 更新 IP 段统计
	if b.config.SubnetEnabled && ip != "" {
		b.checkAndBlockSubnet(ip, now)
	}
}

// recordIPHit 记录 IP 触发
func (b *wafMultiDimBlocker) recordIPHit(ip string, now time.Time) {
	// 获取触发历史
	hits := b.ipHits[ip]

	// 移除过期记录
	validHits := make([]time.Time, 0)
	for _, hitTime := range hits {
		if now.Sub(hitTime) < b.config.IPWindow {
			validHits = append(validHits, hitTime)
		}
	}

	// 添加当前触发
	validHits = append(validHits, now)
	b.ipHits[ip] = validHits

	// 检查是否达到阈值
	if len(validHits) >= b.config.IPMaxHits {
		b.blockIP(ip, fmt.Sprintf("在 %v 内触发 %d 次 WAF 规则", b.config.IPWindow, len(validHits)), b.config.IPBlockDuration, now)
	}
}

// recordTLSHit 记录 TLS 指纹触发
func (b *wafMultiDimBlocker) recordTLSHit(fingerprint, ip string, now time.Time) {
	// 记录 TLS 指纹到 IP 的映射
	if ip != "" {
		ips := b.tlsToIPs[fingerprint]
		found := false
		for _, existingIP := range ips {
			if existingIP == ip {
				found = true
				break
			}
		}
		if !found {
			b.tlsToIPs[fingerprint] = append(ips, ip)
		}
	}

	// 获取触发历史
	hits := b.tlsHits[fingerprint]

	// 移除过期记录
	validHits := make([]time.Time, 0)
	for _, hitTime := range hits {
		if now.Sub(hitTime) < b.config.TLSWindow {
			validHits = append(validHits, hitTime)
		}
	}

	// 添加当前触发
	validHits = append(validHits, now)
	b.tlsHits[fingerprint] = validHits

	// 检查是否达到阈值
	if len(validHits) >= b.config.TLSMaxHits {
		reason := fmt.Sprintf("TLS 指纹在 %v 内触发 %d 次 WAF 规则", b.config.TLSWindow, len(validHits))
		if len(b.tlsToIPs[fingerprint]) > 0 {
			reason += fmt.Sprintf("，涉及 %d 个 IP", len(b.tlsToIPs[fingerprint]))
		}
		b.blockTLS(fingerprint, reason, b.config.TLSBlockDuration, now)
	}
}

// checkAndBlockSubnet 检查并封禁 IP 段
func (b *wafMultiDimBlocker) checkAndBlockSubnet(ip string, now time.Time) {
	// 获取 IP 所属网段
	subnet := getIPSubnet(ip, b.config.SubnetMask)
	if subnet == "" {
		return
	}

	// 检查该 IP 是否已被封禁
	if _, blocked := b.ipBlocked[ip]; !blocked {
		return
	}

	// 统计该网段内被封禁的 IP 数量
	count := 0
	for blockedIP := range b.ipBlocked {
		if isIPInSubnet(blockedIP, subnet) {
			count++
		}
	}

	// 更新网段统计
	b.subnetHits[subnet] = count

	// 检查是否达到阈值
	if count >= b.config.SubnetThreshold {
		// 检查是否已经封禁
		if _, alreadyBlocked := b.subnetBlocked[subnet]; !alreadyBlocked {
			reason := fmt.Sprintf("网段内 %d 个 IP 被封禁", count)
			b.blockSubnet(subnet, reason, b.config.SubnetBlockDuration, now)
		}
	}
}

// blockIP 封禁 IP
func (b *wafMultiDimBlocker) blockIP(ip, reason string, duration time.Duration, now time.Time) {
	expireTime := now.Add(duration)

	record := &BlockRecord{
		Dimension:  DimensionIP,
		Value:      ip,
		Reason:     reason,
		ExpireTime: expireTime,
		HitCount:   len(b.ipHits[ip]),
		FirstSeen:  now,
		LastSeen:   now,
	}

	// 如果已存在，更新记录
	if existing, exists := b.ipBlocked[ip]; exists {
		record.FirstSeen = existing.FirstSeen
		record.HitCount = existing.HitCount + 1
	}

	b.ipBlocked[ip] = record
	b.log.Warnf("WAF 多维度封禁：IP %s 已被封禁，原因：%s，到期时间：%v", ip, reason, expireTime.Format(time.RFC3339))
}

// blockTLS 封禁 TLS 指纹
func (b *wafMultiDimBlocker) blockTLS(fingerprint, reason string, duration time.Duration, now time.Time) {
	expireTime := now.Add(duration)

	record := &BlockRecord{
		Dimension:  DimensionTLS,
		Value:      fingerprint,
		Reason:     reason,
		ExpireTime: expireTime,
		HitCount:   len(b.tlsHits[fingerprint]),
		FirstSeen:  now,
		LastSeen:   now,
	}

	// 如果已存在，更新记录
	if existing, exists := b.tlsBlocked[fingerprint]; exists {
		record.FirstSeen = existing.FirstSeen
		record.HitCount = existing.HitCount + 1
	}

	b.tlsBlocked[fingerprint] = record
	b.log.Warnf("WAF 多维度封禁：TLS 指纹 %s 已被封禁，原因：%s，到期时间：%v", fingerprint[:16]+"...", reason, expireTime.Format(time.RFC3339))
}

// blockSubnet 封禁 IP 段
func (b *wafMultiDimBlocker) blockSubnet(cidr, reason string, duration time.Duration, now time.Time) {
	expireTime := now.Add(duration)

	record := &BlockRecord{
		Dimension:  DimensionSubnet,
		Value:      cidr,
		Reason:     reason,
		ExpireTime: expireTime,
		HitCount:   b.subnetHits[cidr],
		FirstSeen:  now,
		LastSeen:   now,
	}

	// 如果已存在，更新记录
	if existing, exists := b.subnetBlocked[cidr]; exists {
		record.FirstSeen = existing.FirstSeen
		record.HitCount = existing.HitCount + 1
	}

	b.subnetBlocked[cidr] = record
	b.log.Warnf("WAF 多维度封禁：IP 段 %s 已被封禁，原因：%s，到期时间：%v", cidr, reason, expireTime.Format(time.RFC3339))
}

// SetWhitelistChecker 设置白名单检查函数
func (b *wafMultiDimBlocker) SetWhitelistChecker(checker func(ip string) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.whitelistChecker = checker
}

// IsBlocked 检查是否被封禁
func (b *wafMultiDimBlocker) IsBlocked(ip, tlsFingerprint string) (bool, BlockDimension, string) {
	// 先检查白名单，白名单中的IP永远不会被封禁
	if ip != "" && b.whitelistChecker != nil && b.whitelistChecker(ip) {
		return false, "", ""
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()

	// 1. 检查 IP 是否被封禁
	if b.config.IPEnabled && ip != "" {
		if record, exists := b.ipBlocked[ip]; exists {
			if now.Before(record.ExpireTime) {
				return true, DimensionIP, record.Reason
			}
		}
	}

	// 2. 检查 IP 所属网段是否被封禁
	if b.config.SubnetEnabled && ip != "" {
		for cidr, record := range b.subnetBlocked {
			if now.Before(record.ExpireTime) && isIPInSubnet(ip, cidr) {
				return true, DimensionSubnet, fmt.Sprintf("所属网段 %s 被封禁: %s", cidr, record.Reason)
			}
		}
	}

	// 3. 检查 TLS 指纹是否被封禁
	if b.config.TLSEnabled && tlsFingerprint != "" {
		if record, exists := b.tlsBlocked[tlsFingerprint]; exists {
			if now.Before(record.ExpireTime) {
				return true, DimensionTLS, record.Reason
			}
		}
	}

	return false, "", ""
}

// UnblockByDimension 解除封禁
func (b *wafMultiDimBlocker) UnblockByDimension(dimension BlockDimension, value string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch dimension {
	case DimensionIP:
		delete(b.ipBlocked, value)
		delete(b.ipHits, value)
		b.log.Infof("WAF 多维度封禁：已解除 IP %s 的封禁", value)
	case DimensionTLS:
		delete(b.tlsBlocked, value)
		delete(b.tlsHits, value)
		delete(b.tlsToIPs, value)
		b.log.Infof("WAF 多维度封禁：已解除 TLS 指纹 %s 的封禁", value[:16]+"...")
	case DimensionSubnet:
		delete(b.subnetBlocked, value)
		delete(b.subnetHits, value)
		b.log.Infof("WAF 多维度封禁：已解除 IP 段 %s 的封禁", value)
	}
}

// BlockByDimension 手动封禁（公开方法）
func (b *wafMultiDimBlocker) BlockByDimension(dimension BlockDimension, value string, duration time.Duration, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if value == "" {
		return
	}

	now := time.Now()
	if duration == 0 {
		// 永久封禁（设置一个很远的未来时间）
		duration = 100 * 365 * 24 * time.Hour
	}

	switch dimension {
	case DimensionIP:
		b.blockIP(value, reason, duration, now)
	case DimensionTLS:
		b.blockTLS(value, reason, duration, now)
	case DimensionSubnet:
		b.blockSubnet(value, reason, duration, now)
	default:
		b.log.Warnf("WAF 多维度封禁：未知的封禁维度 %s", dimension)
	}
}

// GetBlockedList 获取封禁列表
func (b *wafMultiDimBlocker) GetBlockedList(dimension BlockDimension) []*BlockRecord {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	result := make([]*BlockRecord, 0)

	switch dimension {
	case DimensionIP:
		for _, record := range b.ipBlocked {
			if now.Before(record.ExpireTime) {
				result = append(result, record)
			}
		}
	case DimensionTLS:
		for _, record := range b.tlsBlocked {
			if now.Before(record.ExpireTime) {
				result = append(result, record)
			}
		}
	case DimensionSubnet:
		for _, record := range b.subnetBlocked {
			if now.Before(record.ExpireTime) {
				result = append(result, record)
			}
		}
	case "": // 返回所有维度
		for _, record := range b.ipBlocked {
			if now.Before(record.ExpireTime) {
				result = append(result, record)
			}
		}
		for _, record := range b.tlsBlocked {
			if now.Before(record.ExpireTime) {
				result = append(result, record)
			}
		}
		for _, record := range b.subnetBlocked {
			if now.Before(record.ExpireTime) {
				result = append(result, record)
			}
		}
	}

	return result
}

// GetSubnetStats 获取 IP 段统计
func (b *wafMultiDimBlocker) GetSubnetStats() map[string]int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]int)
	for subnet, count := range b.subnetHits {
		result[subnet] = count
	}
	return result
}

// GetTLSStats 获取 TLS 指纹统计
func (b *wafMultiDimBlocker) GetTLSStats() map[string]int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]int)
	for fingerprint, hits := range b.tlsHits {
		result[fingerprint] = len(hits)
	}
	return result
}

// cleanup 清理过期数据
func (b *wafMultiDimBlocker) cleanup() {
	for {
		select {
		case <-b.cleanupTicker.C:
			b.doCleanup()
		case <-b.stopChan:
			return
		}
	}
}

// doCleanup 执行清理
func (b *wafMultiDimBlocker) doCleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	// 清理过期的 IP 封禁
	for ip, record := range b.ipBlocked {
		if now.After(record.ExpireTime) {
			delete(b.ipBlocked, ip)
		}
	}

	// 清理过期的 TLS 指纹封禁
	for fingerprint, record := range b.tlsBlocked {
		if now.After(record.ExpireTime) {
			delete(b.tlsBlocked, fingerprint)
		}
	}

	// 清理过期的 IP 段封禁
	for cidr, record := range b.subnetBlocked {
		if now.After(record.ExpireTime) {
			delete(b.subnetBlocked, cidr)
		}
	}

	// 清理过期的触发历史
	for ip, hits := range b.ipHits {
		validHits := make([]time.Time, 0)
		for _, hitTime := range hits {
			if now.Sub(hitTime) < b.config.IPWindow*2 {
				validHits = append(validHits, hitTime)
			}
		}
		if len(validHits) > 0 {
			b.ipHits[ip] = validHits
		} else {
			delete(b.ipHits, ip)
		}
	}

	for fingerprint, hits := range b.tlsHits {
		validHits := make([]time.Time, 0)
		for _, hitTime := range hits {
			if now.Sub(hitTime) < b.config.TLSWindow*2 {
				validHits = append(validHits, hitTime)
			}
		}
		if len(validHits) > 0 {
			b.tlsHits[fingerprint] = validHits
		} else {
			delete(b.tlsHits, fingerprint)
			delete(b.tlsToIPs, fingerprint)
		}
	}
}

// Stop 停止封禁器
func (b *wafMultiDimBlocker) Stop() {
	if b.stopChan != nil {
		close(b.stopChan)
	}
	if b.cleanupTicker != nil {
		b.cleanupTicker.Stop()
	}
}

// getIPSubnet 获取 IP 所属的网段
func getIPSubnet(ip string, mask int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	// 转换为 IPv4
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return "" // 暂不支持 IPv6
	}

	// 生成 CIDR
	cidr := fmt.Sprintf("%s/%d",
		ipv4.Mask(net.CIDRMask(mask, 32)).String(),
		mask)
	return cidr
}

// isIPInSubnet 检查 IP 是否在指定网段内
func isIPInSubnet(ip string, cidr string) bool {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	return subnet.Contains(parsed)
}

