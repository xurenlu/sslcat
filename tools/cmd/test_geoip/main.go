package main

import (
	"fmt"
	"log"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
)

func main() {
	// 测试IP列表
	testIPs := []string{
		"8.8.8.8",         // Google DNS (美国)
		"1.1.1.1",         // Cloudflare DNS (美国)
		"114.114.114.114", // 114DNS (中国)
		"223.5.5.5",       // 阿里DNS (中国)
		"208.67.222.222",  // OpenDNS (美国)
		"180.76.76.76",    // 百度DNS (中国)
	}

	fmt.Println("🌍 SSLcat GeoIP 功能测试")
	fmt.Println("========================")
	fmt.Println()

	// 创建GeoIP服务配置
	geoConfig := config.GeoBlockingConfig{
		Enabled:          true,
		DatabasePath:     "./data/geoip/GeoLite2-City.mmdb",
		AllowedCountries: []string{"CN", "US"},
		BlockedCountries: []string{},
		AllowUnknown:     true,
	}

	// 初始化GeoIP服务
	geoService, err := security.NewGeoIPService(geoConfig)
	if err != nil {
		log.Fatalf("❌ 初始化GeoIP服务失败: %v", err)
	}
	defer geoService.Close()

	fmt.Println("✅ GeoIP服务初始化成功")
	fmt.Println()

	// 显示服务状态
	stats := geoService.GetStats()
	fmt.Printf("📊 服务状态:\n")
	fmt.Printf("  - 功能启用: %v\n", stats["enabled"])
	fmt.Printf("  - 城市数据库: %v\n", stats["city_db_loaded"])
	fmt.Printf("  - ASN数据库: %v\n", stats["asn_db_loaded"])
	fmt.Printf("  - 缓存大小: %v/%v\n", stats["cache_size"], stats["cache_max_size"])
	fmt.Printf("  - 允许国家: %v\n", stats["allowed_countries"])
	fmt.Printf("  - 阻止国家: %v\n", stats["blocked_countries"])
	fmt.Println()

	// 测试每个IP
	fmt.Println("🔍 IP地理位置查询测试:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%-15s %-12s %-20s %-15s %-25s %-8s\n",
		"IP地址", "国家代码", "国家", "城市", "ISP", "访问权限")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for _, ip := range testIPs {
		// 获取地理位置信息
		location, err := geoService.GetLocation(ip)
		if err != nil {
			fmt.Printf("%-15s %-12s %-20s %-15s %-25s %-8s\n",
				ip, "ERROR", err.Error(), "", "", "")
			continue
		}

		// 检查访问权限
		result, err := geoService.CheckCountryAccess(ip)
		if err != nil {
			fmt.Printf("%-15s %-12s %-20s %-15s %-25s %-8s\n",
				ip, location.CountryCode, location.Country, location.City,
				location.ISP, "ERROR")
			continue
		}

		accessStatus := "🚫拒绝"
		if result.Allowed {
			accessStatus = "✅允许"
		}

		// 截断过长的字符串
		country := location.Country
		if len(country) > 18 {
			country = country[:15] + "..."
		}

		city := location.City
		if len(city) > 13 {
			city = city[:10] + "..."
		}

		isp := location.ISP
		if len(isp) > 23 {
			isp = isp[:20] + "..."
		}

		fmt.Printf("%-15s %-12s %-20s %-15s %-25s %-8s\n",
			ip, location.CountryCode, country, city, isp, accessStatus)
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// 测试不同的过滤策略
	fmt.Println("🛡️ 过滤策略测试:")
	fmt.Println()

	// 测试1: 只允许中国
	fmt.Println("📋 策略1: 只允许中国 (CN)")
	testFilterPolicy(geoService, []string{"CN"}, []string{}, testIPs[:3])

	// 测试2: 阻止美国
	fmt.Println("📋 策略2: 阻止美国 (US)")
	testFilterPolicy(geoService, []string{}, []string{"US"}, testIPs[:3])

	fmt.Println("✅ 测试完成！")
}

// testFilterPolicy 测试过滤策略
func testFilterPolicy(geoService *security.GeoIPService, allowed, blocked []string, testIPs []string) {
	// 创建新的配置
	newConfig := config.GeoBlockingConfig{
		Enabled:          true,
		DatabasePath:     "./data/geoip/GeoLite2-City.mmdb",
		AllowedCountries: allowed,
		BlockedCountries: blocked,
		AllowUnknown:     false,
	}

	// 更新配置
	if err := geoService.UpdateGeoConfig(newConfig); err != nil {
		fmt.Printf("❌ 更新配置失败: %v\n", err)
		return
	}

	for _, ip := range testIPs {
		result, err := geoService.CheckCountryAccess(ip)
		if err != nil {
			fmt.Printf("  %s: ❌ 错误 - %v\n", ip, err)
			continue
		}

		status := "🚫拒绝"
		if result.Allowed {
			status = "✅允许"
		}

		fmt.Printf("  %s (%s): %s - %s\n",
			ip, result.Country, status, result.Reason)
	}
	fmt.Println()
}
