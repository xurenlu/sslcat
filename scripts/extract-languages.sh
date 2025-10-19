#!/bin/bash

# 语言配置
declare -A languages=(
    ["zhCN"]="zh-cn"
    ["enUS"]="en-us" 
    ["jaJP"]="ja-jp"
    ["esES"]="es-es"
    ["frFR"]="fr-fr"
    ["koKR"]="ko-kr"
    ["deDE"]="de-de"
    ["ruRU"]="ru-ru"
    ["zhTW"]="zh-tw"
)

# 为每种语言创建文件
for lang_var in "${!languages[@]}"; do
    lang_file="${languages[$lang_var]}"
    echo "Creating $lang_file.ts..."
    
    # 创建文件头部
    cat > "frontend/src/i18n/languages/$lang_file.ts" << EOF
import { Translation } from './types';

export const $lang_var: Translation = {
EOF

    # 提取翻译内容
    sed -n "/^export const $lang_var: Translation = {$/,/^};$/p" frontend/src/i18n/index.ts | \
    sed '1d;$d' >> "frontend/src/i18n/languages/$lang_file.ts"
    
    # 添加文件尾部
    echo "};" >> "frontend/src/i18n/languages/$lang_file.ts"
    
    echo "Created $lang_file.ts"
done

echo "All language files created successfully!"
