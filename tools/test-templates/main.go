package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	templatesDir    = flag.String("templates-dir", "internal/runner/templates/builtin", "模板目录路径")
	category        = flag.String("category", "", "按分类过滤（可选）")
	templateID      = flag.String("template", "", "测试单个模板（可选）")
	parallel        = flag.Int("parallel", 2, "并发数（默认2-3）")
	outputDir       = flag.String("output-dir", "./test-results", "输出目录")
	timeoutStr      = flag.String("timeout", "10m", "容器启动超时（如：5m, 10m）")
	skipImageCheck = flag.Bool("skip-image-check", false, "跳过镜像检查")
	skipContentCheck = flag.Bool("skip-content-check", false, "跳过内容验证")
	basePort        = flag.Int("base-port", 20000, "测试端口起始值")
	cleanup         = flag.Bool("cleanup", true, "测试后清理容器（默认true）")
	priorityOnly    = flag.String("priority", "", "只测试指定优先级（high/medium/low）")
)

func main() {
	flag.Parse()

	// 解析超时时间
	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		fmt.Printf("❌ 无效的超时时间: %v\n", err)
		os.Exit(1)
	}

	// 设置日志
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	fmt.Println("🔍 开始扫描模板...")

	// 初始化扫描器
	scanner := NewScanner(*templatesDir)
	templates, err := scanner.ScanTemplates()
	if err != nil {
		fmt.Printf("❌ 扫描模板失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("📦 找到 %d 个模板\n", len(templates))

	// 过滤模板
	if *category != "" {
		templates = FilterByCategory(templates, *category)
		fmt.Printf("📂 按分类 '%s' 过滤后: %d 个模板\n", *category, len(templates))
	}

	if *templateID != "" {
		templates = FilterByTemplateID(templates, *templateID)
		fmt.Printf("🎯 按模板 ID '%s' 过滤后: %d 个模板\n", *templateID, len(templates))
	}

	// 按优先级过滤
	if *priorityOnly != "" {
		var targetPriority TemplatePriority
		switch strings.ToLower(*priorityOnly) {
		case "high":
			targetPriority = PriorityHigh
		case "medium":
			targetPriority = PriorityMedium
		case "low":
			targetPriority = PriorityLow
		default:
			fmt.Printf("⚠️  无效的优先级: %s，使用全部模板\n", *priorityOnly)
		}
		if targetPriority > 0 {
			filtered := []TemplateInfo{}
			for _, tpl := range templates {
				if GetTemplatePriority(&tpl) == targetPriority {
					filtered = append(filtered, tpl)
				}
			}
			templates = filtered
			fmt.Printf("🎯 按优先级 '%s' 过滤后: %d 个模板\n", *priorityOnly, len(templates))
		}
	}

	if len(templates) == 0 {
		fmt.Println("⚠️  没有找到匹配的模板")
		os.Exit(0)
	}

	// 按优先级排序
	templates = SortTemplatesByPriority(templates)
	
	// 按优先级分组
	priorityGroups := GroupTemplatesByPriority(templates)
	fmt.Printf("📊 按优先级分组: ")
	for priority, tpls := range priorityGroups {
		priorityName := "低"
		if priority == PriorityHigh {
			priorityName = "高"
		} else if priority == PriorityMedium {
			priorityName = "中"
		}
		fmt.Printf("%s优先级(%d) ", priorityName, len(tpls))
	}
	fmt.Println()
	
	// 按分类分组（用于统计）
	groups := GroupByCategory(templates)
	fmt.Printf("📦 按分类分组: ")
	for cat, tpls := range groups {
		fmt.Printf("%s(%d) ", cat, len(tpls))
	}
	fmt.Println()

	// 初始化组件
	imageChecker := NewImageChecker()
	composeGen := NewComposeGenerator(*basePort)
	containerMgr := NewContainerManager(timeout)
	portChecker := NewPortChecker(5*time.Second, 3)
	contentValidator := NewContentValidator(10)
	reportGen := NewReportGenerator(*outputDir)

	// 处理信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 开始测试
	startTime := time.Now()
	results := make([]TestResult, 0, len(templates))
	var resultsMu sync.Mutex

	// 并发控制
	semaphore := make(chan struct{}, *parallel)
	var wg sync.WaitGroup

	// 端口计数器
	portCounter := *basePort
	var portMu sync.Mutex

	for _, template := range templates {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(tpl TemplateInfo) {
			defer func() {
				<-semaphore
				wg.Done()
				// 确保清理资源，即使发生 panic
				if r := recover(); r != nil {
					fmt.Printf("❌ 模板 %s 测试时发生 panic: %v\n", tpl.Name, r)
				}
			}()

			// 分配端口
			portMu.Lock()
			testPort := portCounter
			portCounter++
			portMu.Unlock()

			// 测试模板，失败时继续执行（不中断其他测试）
			result := testTemplate(
				&tpl,
				scanner,
				imageChecker,
				composeGen,
				containerMgr,
				portChecker,
				contentValidator,
				testPort,
				timeout,
			)

			// 无论成功失败都记录结果
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}(template)
	}

	// 等待所有测试完成或收到信号
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-sigChan:
		fmt.Println("\n⚠️  收到中断信号，正在清理...")
		// 这里可以添加清理逻辑
		os.Exit(1)
	case <-done:
		// 测试完成
	}

	// 生成报告
	if err := reportGen.GenerateReport(results, startTime); err != nil {
		fmt.Printf("❌ 生成报告失败: %v\n", err)
		os.Exit(1)
	}
}

// testTemplate 测试单个模板
func testTemplate(
	template *TemplateInfo,
	scanner *Scanner,
	imageChecker *ImageChecker,
	composeGen *ComposeGenerator,
	containerMgr *ContainerManager,
	portChecker *PortChecker,
	contentValidator *ContentValidator,
	testPort int,
	timeout time.Duration,
) TestResult {
	priority := GetTemplatePriority(template)
	priorityStr := "low"
	if priority == PriorityHigh {
		priorityStr = "high"
	} else if priority == PriorityMedium {
		priorityStr = "medium"
	}

	result := TestResult{
		TemplateID:   template.ID,
		TemplateName: template.Name,
		Category:     template.Category,
		Subcategory:  template.Subcategory,
		Priority:     priorityStr,
		Status:       StatusPending,
		Stages:       make(map[string]StageStatus),
		Errors:       []string{},
		Warnings:     []string{},
		StartTime:    time.Now(),
		ImageNames:   []string{},
	}

	defer func() {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
	}()

	fmt.Printf("\n🧪 测试模板: %s (%s)\n", template.Name, template.ID)

	// 阶段1: 加载模板元数据和 Compose 文件
	stageStart := time.Now()
	meta, err := scanner.LoadTemplateMeta(template)
	if err != nil {
		result.Status = StatusFailed
		result.Errors = append(result.Errors, fmt.Sprintf("加载模板元数据失败: %v", err))
		result.Stages["load_meta"] = StageStatus{
			Status:   StatusFailed,
			Duration: time.Since(stageStart).String(),
			Error:    err.Error(),
		}
		return result
	}

	compose, err := scanner.LoadComposeFile(template)
	if err != nil {
		result.Status = StatusFailed
		result.Errors = append(result.Errors, fmt.Sprintf("加载 Compose 文件失败: %v", err))
		result.Stages["load_compose"] = StageStatus{
			Status:   StatusFailed,
			Duration: time.Since(stageStart).String(),
			Error:    err.Error(),
		}
		return result
	}

	result.Stages["load"] = StageStatus{
		Status:   StatusPassed,
		Duration: time.Since(stageStart).String(),
	}

	// 阶段2: 镜像检查
	if !*skipImageCheck {
		stageStart = time.Now()
		images := ExtractImages(compose)
		
		// 构建变量映射用于替换
		variables := make(map[string]string)
		for _, v := range meta.Variables {
			if v.Default != nil {
				variables[v.Name] = fmt.Sprintf("%v", v.Default)
			}
		}

		for _, image := range images {
			replacedImage := ReplaceImageVariables(image, variables)
			result.ImageNames = append(result.ImageNames, replacedImage)
			exists, err := imageChecker.CheckImage(replacedImage)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("检查镜像 %s 失败: %v", replacedImage, err))
			}
			if !exists {
				result.Status = StatusSkipped
				result.Errors = append(result.Errors, fmt.Sprintf("镜像不存在: %s", replacedImage))
				result.Stages["image_check"] = StageStatus{
					Status:   StatusSkipped,
					Duration: time.Since(stageStart).String(),
					Error:    fmt.Sprintf("镜像不存在: %s", replacedImage),
				}
				// 失败时继续，不中断测试流程
				return result
			}
		}

		result.Stages["image_check"] = StageStatus{
			Status:   StatusPassed,
			Duration: time.Since(stageStart).String(),
		}
		PrintStageResult(template.Name, "镜像检查", StatusPassed, time.Since(stageStart), nil)
	}

	// 阶段3: 生成 Compose 文件
	stageStart = time.Now()
	workDir, err := composeGen.Generate(template, meta, compose, testPort)
	if err != nil {
		result.Status = StatusFailed
		result.Errors = append(result.Errors, fmt.Sprintf("生成 Compose 文件失败: %v", err))
		result.Stages["compose_generation"] = StageStatus{
			Status:   StatusFailed,
			Duration: time.Since(stageStart).String(),
			Error:    err.Error(),
		}
		return result
	}

	// 确保清理
	if *cleanup {
		defer func() {
			if err := containerMgr.StopContainers(workDir); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("清理容器失败: %v", err))
			}
		}()
	}

	result.Stages["compose_generation"] = StageStatus{
		Status:   StatusPassed,
		Duration: time.Since(stageStart).String(),
	}
	PrintStageResult(template.Name, "Compose 生成", StatusPassed, time.Since(stageStart), nil)

	// 阶段4: 启动容器
	stageStart = time.Now()
	result.Status = StatusRunning
	if err := containerMgr.StartContainers(workDir); err != nil {
		result.Status = StatusFailed
		result.Errors = append(result.Errors, fmt.Sprintf("启动容器失败: %v", err))
		result.Stages["container_start"] = StageStatus{
			Status:   StatusFailed,
			Duration: time.Since(stageStart).String(),
			Error:    err.Error(),
		}
		return result
	}

	// 等待容器健康
	healthTimeout := timeout
	if meta.Healthcheck.Timeout > 0 {
		healthTimeout = meta.Healthcheck.Timeout
	}
	if healthTimeout == 0 {
		healthTimeout = 5 * time.Minute
	}

	if err := containerMgr.WaitForHealthy(workDir, healthTimeout); err != nil {
		result.Status = StatusFailed
		result.Errors = append(result.Errors, fmt.Sprintf("等待容器健康失败: %v", err))
		
		// 获取日志
		logs, logErr := containerMgr.GetContainerLogs(workDir, "", 50)
		if logErr == nil {
			result.Errors = append(result.Errors, fmt.Sprintf("容器日志: %s", logs))
		}
		
		result.Stages["container_start"] = StageStatus{
			Status:   StatusFailed,
			Duration: time.Since(stageStart).String(),
			Error:    err.Error(),
		}
		return result
	}

	result.Stages["container_start"] = StageStatus{
		Status:   StatusPassed,
		Duration: time.Since(stageStart).String(),
	}
	PrintStageResult(template.Name, "容器启动", StatusPassed, time.Since(stageStart), nil)

	// 阶段5: 端口检查
	stageStart = time.Now()
	ports := ExtractPorts(meta.Services)
	if len(ports) == 0 {
		result.Warnings = append(result.Warnings, "未找到可检查的端口")
	} else {
		// 从生成的 compose 文件获取实际端口映射
		portMap, err := composeGen.GetMappedPorts(workDir)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("获取端口映射失败: %v，使用默认端口", err))
			portMap = make(map[string]int)
			// 使用第一个服务的端口
			if len(meta.Services) > 0 && len(meta.Services[0].Ports) > 0 {
				portMap[meta.Services[0].Name] = testPort
			}
		}

		allPortsOK := true
		for i, service := range meta.Services {
			if len(service.Ports) == 0 {
				continue
			}

			// 获取该服务映射的外部端口
			actualPort := testPort
			if mappedPort, ok := portMap[service.Name]; ok {
				actualPort = mappedPort
			} else if i == 0 {
				// 第一个服务使用 testPort
				actualPort = testPort
			}

			// 检查端口
			protocol := "tcp"
			if len(service.Ports) > 0 && service.Ports[0].Protocol != "" {
				protocol = service.Ports[0].Protocol
			}

			ok, err := portChecker.CheckPort(actualPort, protocol)
			if !ok {
				allPortsOK = false
				result.Errors = append(result.Errors, fmt.Sprintf("端口 %d (%s) 不可访问: %v", actualPort, service.Name, err))
			}
		}

		if !allPortsOK {
			result.Status = StatusFailed
			result.Stages["port_check"] = StageStatus{
				Status:   StatusFailed,
				Duration: time.Since(stageStart).String(),
				Error:    "部分端口不可访问",
			}
			return result
		}
	}

	result.Stages["port_check"] = StageStatus{
		Status:   StatusPassed,
		Duration: time.Since(stageStart).String(),
	}
	PrintStageResult(template.Name, "端口检查", StatusPassed, time.Since(stageStart), nil)

	// 阶段6: 内容验证
	if !*skipContentCheck && len(ports) > 0 {
		stageStart = time.Now()
		keywords := ExtractKeywords(template.Name)
		if len(keywords) > 0 {
			// 从端口映射获取实际端口
			portMap, err := composeGen.GetMappedPorts(workDir)
			if err == nil && len(portMap) > 0 {
				// 使用第一个服务的端口
				var testPortForHTTP int
				for _, port := range portMap {
					testPortForHTTP = port
					break
				}
				testURL := fmt.Sprintf("http://localhost:%d", testPortForHTTP)
				matched, matchedKeywords, err := contentValidator.Validate(testURL, keywords)
				if err != nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("内容验证失败: %v", err))
				} else if !matched {
					result.Warnings = append(result.Warnings, fmt.Sprintf("未找到关键词: %v", keywords))
				} else {
					result.Stages["content_validation"] = StageStatus{
						Status:   StatusPassed,
						Duration: time.Since(stageStart).String(),
						Message:  fmt.Sprintf("匹配关键词: %v", matchedKeywords),
					}
					PrintStageResult(template.Name, "内容验证", StatusPassed, time.Since(stageStart), nil)
				}
			} else {
				result.Warnings = append(result.Warnings, "无法获取端口映射，跳过内容验证")
			}
		}
	}

	// 测试通过
	result.Status = StatusPassed
	fmt.Printf("✅ %s - 测试通过 (总耗时: %s)\n", template.Name, result.Duration)
	return result
}

