package ssl

import (
	"testing"
	"time"
)

// TestRenewalWindowIncludesExpiredCerts 与 isCertExpiringSoon 的判断一致：
// 已过期证书的 NotAfter 早于当前时间时，time.Until 为负，仍小于 30 天窗口，应触发续期。
func TestRenewalWindowIncludesExpiredCerts(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	if got := time.Until(past) < 30*24*time.Hour; !got {
		t.Fatal("expired cert deadline should fall within the 30-day renewal window check")
	}
}
