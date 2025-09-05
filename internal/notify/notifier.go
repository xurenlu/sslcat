package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Notifier struct {
	webhookURL string
	syslogAddr string
	lokiURL    string
	httpClient *http.Client
	hostname   string
}

func NewFromEnv() *Notifier {
	n := &Notifier{
		webhookURL: strings.TrimSpace(os.Getenv("WITHSSL_WEBHOOK_URL")),
		syslogAddr: strings.TrimSpace(os.Getenv("WITHSSL_SYSLOG_ADDR")), // host:port (udp)
		lokiURL:    strings.TrimSpace(os.Getenv("WITHSSL_LOKI_URL")),    // http(s)://host:3100/loki/api/v1/push
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	if h, _ := os.Hostname(); h != "" {
		n.hostname = h
	} else {
		n.hostname = "withssl"
	}
	return n
}

func (n *Notifier) Enabled() bool {
	return n != nil && (n.webhookURL != "" || n.syslogAddr != "" || n.lokiURL != "")
}

func (n *Notifier) SendJSON(v map[string]any) {
	if n == nil {
		return
	}
	// webhook
	if n.webhookURL != "" {
		b, _ := json.Marshal(v)
		req, _ := http.NewRequest(http.MethodPost, n.webhookURL, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		n.httpClient.Do(req) // 忽略错误，尽量不影响主流程
	}
	// syslog (UDP 简化)
	if n.syslogAddr != "" {
		line, _ := json.Marshal(v)
		msg := fmt.Sprintf("<14>%s withssl: %s", time.Now().Format(time.RFC3339), string(line))
		_ = sendUDP(n.syslogAddr, []byte(msg))
	}
	// loki
	if n.lokiURL != "" {
		n.sendLoki(v)
	}
}

func sendUDP(addr string, payload []byte) error {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(payload)
	return err
}

func (n *Notifier) sendLoki(v map[string]any) {
	b, _ := json.Marshal(v)
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	payload := map[string]any{
		"streams": []any{map[string]any{
			"stream": map[string]string{"job": "withssl", "host": n.hostname},
			"values": [][]string{{ts, string(b)}},
		}},
	}
	pb, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, n.lokiURL, bytes.NewReader(pb))
	req.Header.Set("Content-Type", "application/json")
	n.httpClient.Do(req)
}
