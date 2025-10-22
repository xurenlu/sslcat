#!/usr/bin/env python3
"""
批量将docs目录中的YAML配置示例转换为JSON格式
"""
import os
import re
import json
import yaml
from pathlib import Path

def yaml_to_json(yaml_text):
    """将YAML文本转换为JSON格式"""
    try:
        # 解析YAML
        data = yaml.safe_load(yaml_text)
        # 转换为JSON，保持缩进
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"转换失败: {e}")
        return yaml_text

def fix_yaml_blocks(content):
    """修复内容中的YAML代码块"""
    # 匹配 ```yaml 到 ``` 的代码块
    pattern = r'```yaml\n(.*?)\n```'
    
    def replace_yaml_block(match):
        yaml_content = match.group(1)
        # 跳过注释行
        if yaml_content.strip().startswith('#'):
            return match.group(0)
        
        # 转换YAML为JSON
        json_content = yaml_to_json(yaml_content)
        return f'```json\n{json_content}\n```'
    
    return re.sub(pattern, replace_yaml_block, content, flags=re.DOTALL)

def fix_yaml_references(content):
    """修复YAML格式的引用"""
    replacements = [
        (r'YAML 格式', 'JSON 格式'),
        (r'YAML 语法', 'JSON 语法'),
        (r'YAML 文件', 'JSON 文件'),
        (r'YAML 配置', 'JSON 配置'),
        (r'YAML-based', 'JSON-based'),
        (r'YAML files', 'JSON files'),
        (r'YAML configuration', 'JSON configuration'),
        (r'YAML format', 'JSON format'),
        (r'YAML syntax', 'JSON syntax'),
        (r'检查 YAML 语法', '检查 JSON 语法'),
        (r'Check YAML syntax', 'Check JSON syntax'),
        (r'python -c "import yaml; yaml.safe_load', 'python -c "import json; json.load'),
        (r'Validate YAML syntax', 'Validate JSON syntax'),
    ]
    
    for old, new in replacements:
        content = content.replace(old, new)
    
    return content

def process_file(file_path):
    """处理单个文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 跳过docker-compose.yml等文件，只处理配置文件相关的内容
        if 'docker-compose' in content or 'prometheus.yml' in content or 'application.yml' in content:
            return False
        
        original_content = content
        
        # 修复YAML代码块
        content = fix_yaml_blocks(content)
        
        # 修复YAML引用
        content = fix_yaml_references(content)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"已修复: {file_path}")
            return True
        
        return False
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")
        return False

def main():
    """主函数"""
    docs_dir = Path("docs")
    fixed_count = 0
    
    # 处理所有markdown文件
    for md_file in docs_dir.rglob("*.md"):
        if process_file(md_file):
            fixed_count += 1
    
    print(f"\n总共修复了 {fixed_count} 个文件")

if __name__ == "__main__":
    main()
