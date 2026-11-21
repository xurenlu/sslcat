# PHP 站点级指令

PHP 站点可以通过 `php_admin_ini` 设置允许的 PHP 指令。例如：

```json
{
  "domain": "example.test",
  "root": "/var/www/example",
  "fcgi_addr": "unix:/run/php-fpm.sock",
  "php_admin_ini": {
    "memory_limit": "128M",
    "session.upload_progress.enabled": "0"
  }
}
```

管理 API 的 POST / PUT 会校验白名单、规范化指令名，并在持久化前拒绝重复键名和包含 CR、LF、NUL 的值。空值省略。实际效果取决于 PHP-FPM 版本及其允许的指令；SSLcat 不替代 PHP 升级或安全补丁。

指令通过 FastCGI `PHP_ADMIN_VALUE` 下发。`vars` 继续支持普通环境变量，但保留参数 `PHP_VALUE`、`PHP_ADMIN_VALUE`（包括大小写变体）不再透传；已有原始覆盖项需要迁移到 `php_admin_ini`。`auto_prepend_file` 等不在白名单中的指令不能通过本功能配置。

直接编辑配置文件仍须保证指令合法。请求转发时若发现整组指令校验失败，将记录警告并省略该组 `PHP_ADMIN_VALUE`，继续由 PHP-FPM 默认配置处理；这不表示期望的限制已生效。不要将此功能作为唯一安全边界。

`TestPHPAdminValueAppliesToRealFPM` 是可选集成测试，需要提供 `PHPTEST_FCGI` 与 `PHPTEST_SCRIPT`，并保证该脚本在测试 FPM 文件系统中可访问。未提供环境时会跳过，不代表真实 FPM 已验证；普通参数与 API 单测无需启动 FPM。
