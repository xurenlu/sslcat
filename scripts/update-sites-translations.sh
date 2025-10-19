#!/bin/bash

# 更新所有语言文件的 sites 翻译

languages=("ja-jp" "es-es" "fr-fr" "ko-kr" "de-de" "ru-ru")

# 日语
cat > temp_ja_sites.txt << 'EOF'
  sites: {
    title: 'サイト管理',
    staticSites: '静的サイト',
    phpSites: 'PHP サイト',
    refresh: '更新',
    updateSite: 'サイト更新',
    createSite: 'サイト作成',
  },
EOF

# 西班牙语
cat > temp_es_sites.txt << 'EOF'
  sites: {
    title: 'Gestión de Sitios',
    staticSites: 'Sitios Estáticos',
    phpSites: 'Sitios PHP',
    refresh: 'Actualizar',
    updateSite: 'Actualizar Sitio',
    createSite: 'Crear Sitio',
  },
EOF

# 法语
cat > temp_fr_sites.txt << 'EOF'
  sites: {
    title: 'Gestion des Sites',
    staticSites: 'Sites Statiques',
    phpSites: 'Sites PHP',
    refresh: 'Actualiser',
    updateSite: 'Mettre à jour le Site',
    createSite: 'Créer un Site',
  },
EOF

# 韩语
cat > temp_ko_sites.txt << 'EOF'
  sites: {
    title: '사이트 관리',
    staticSites: '정적 사이트',
    phpSites: 'PHP 사이트',
    refresh: '새로고침',
    updateSite: '사이트 업데이트',
    createSite: '사이트 생성',
  },
EOF

# 德语
cat > temp_de_sites.txt << 'EOF'
  sites: {
    title: 'Website-Verwaltung',
    staticSites: 'Statische Websites',
    phpSites: 'PHP Websites',
    refresh: 'Aktualisieren',
    updateSite: 'Website Aktualisieren',
    createSite: 'Website Erstellen',
  },
EOF

# 俄语
cat > temp_ru_sites.txt << 'EOF'
  sites: {
    title: 'Управление Сайтами',
    staticSites: 'Статические Сайты',
    phpSites: 'PHP Сайты',
    refresh: 'Обновить',
    updateSite: 'Обновить Сайт',
    createSite: 'Создать Сайт',
  },
EOF

# 更新文件
for lang in "${languages[@]}"; do
  case $lang in
    "ja-jp")
      sed -i '/sites: {/,/},/c\
'"$(cat temp_ja_sites.txt)" frontend/src/i18n/languages/ja-jp.ts
      ;;
    "es-es")
      sed -i '/sites: {/,/},/c\
'"$(cat temp_es_sites.txt)" frontend/src/i18n/languages/es-es.ts
      ;;
    "fr-fr")
      sed -i '/sites: {/,/},/c\
'"$(cat temp_fr_sites.txt)" frontend/src/i18n/languages/fr-fr.ts
      ;;
    "ko-kr")
      sed -i '/sites: {/,/},/c\
'"$(cat temp_ko_sites.txt)" frontend/src/i18n/languages/ko-kr.ts
      ;;
    "de-de")
      sed -i '/sites: {/,/},/c\
'"$(cat temp_de_sites.txt)" frontend/src/i18n/languages/de-de.ts
      ;;
    "ru-ru")
      sed -i '/sites: {/,/},/c\
'"$(cat temp_ru_sites.txt)" frontend/src/i18n/languages/ru-ru.ts
      ;;
  esac
done

# 清理临时文件
rm -f temp_*_sites.txt

echo "All language files updated successfully!"
