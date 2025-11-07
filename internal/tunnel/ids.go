package tunnel

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var idCounter atomic.Uint64

// GenerateProviderID 生成隧道提供商唯一 ID
func GenerateProviderID(providerType string) string {
	providerType = strings.TrimSpace(providerType)
	if providerType == "" {
		providerType = "provider"
	}

	return fmt.Sprintf("%s-%d-%d", strings.ToLower(providerType), time.Now().UnixNano(), idCounter.Add(1))
}

// GenerateTunnelID 生成隧道唯一 ID
func GenerateTunnelID(providerID string) string {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		providerID = "tunnel"
	}

	return fmt.Sprintf("%s-%d-%d", providerID, time.Now().UnixNano(), idCounter.Add(1))
}
