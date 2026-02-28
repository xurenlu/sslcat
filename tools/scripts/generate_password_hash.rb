#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bcrypt'

# 生成密码的 bcrypt hash
# 用于 SSLcat 用户密码重置
#
# 用法 / Usage:
#   ruby generate_password_hash.rb "your_password"
#   ruby generate_password_hash.rb
#
# 示例 / Example:
#   ruby generate_password_hash.rb "MySecurePass123!"

def generate_hash(password)
  BCrypt::Password.create(password, cost: BCrypt::Engine::DEFAULT_COST)
end

def main
  password = if ARGV[0]
               ARGV[0]
             else
               print '请输入密码 / Enter password: '
               gets.chomp
             end

  if password.empty?
    puts '错误 / Error: 密码不能为空 / Password cannot be empty'
    exit 1
  end

  hash = generate_hash(password)

  puts "\n=== Password Hash Generated / 密码 Hash 已生成 ==="
  puts "\n密码 / Password: #{password}"
  puts "Hash / 哈希值: #{hash}"
  puts "\n使用方法 / Usage:"
  puts 'sqlite3 /opt/sslcat/data/users.db'
  puts "UPDATE users SET password = '#{hash}' WHERE username = 'admin';"
  puts ".quit"
  puts "\n或者使用 Go 工具 / Or use Go tool:"
  puts "go run tools/cmd/reset_password/main.go admin '#{password}'"
end

main if __FILE__ == $PROGRAM_NAME
