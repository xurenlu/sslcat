#!/bin/bash

# 从原始文件中提取每个语言的翻译
# 参数: 语言变量名 起始行 结束行 输出文件名

extract_language() {
    local lang_var=$1
    local start_line=$2
    local end_line=$3
    local output_file=$4
    
    echo "Extracting $lang_var from lines $start_line to $end_line..."
    
    # 创建文件头
    cat > "frontend/src/i18n/languages/$output_file" << EOF
import { Translation } from './types';

EOF
    
    # 提取内容（不包括最后的 export const translations 部分）
    git show HEAD:frontend/src/i18n/index.ts | sed -n "${start_line},${end_line}p" >> "frontend/src/i18n/languages/$output_file"
    
    # 添加分号
    echo ";" >> "frontend/src/i18n/languages/$output_file"
    
    echo "Created $output_file"
}

# 提取每个语言
extract_language "zhCN" "857" "1675" "zh-cn.ts"
extract_language "enUS" "1676" "2494" "en-us.ts"
extract_language "jaJP" "2495" "3307" "ja-jp.ts"
extract_language "esES" "3308" "4120" "es-es.ts"
extract_language "frFR" "4121" "4933" "fr-fr.ts"
extract_language "koKR" "4934" "5746" "ko-kr.ts"
extract_language "deDE" "5747" "6559" "de-de.ts"
extract_language "ruRU" "6560" "7372" "ru-ru.ts"
extract_language "zhTW" "7373" "8185" "zh-tw.ts"

echo "All language files extracted successfully!"
