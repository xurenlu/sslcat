#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// 所有需要添加的字段及其翻译
const translations = {
  'en-us': {
    common: {
      creating: 'Creating...',
      saving: 'Saving...'
    },
    proxy: {
      username: 'Username',
      password: 'Password',
      performance_monitoring: 'Performance Monitoring',
      enable_tracing: 'Enable Request Tracing',
      enable_metrics: 'Enable Metrics Collection',
      tracing_warning: '⚠️ Enabling will significantly increase CPU usage, recommended for debugging only',
      metrics_warning: '⚠️ Enabling will increase CPU usage, recommended for monitoring only'
    },
    sites: {
      edit: 'Edit',
      delete: 'Delete'
    },
    dns: {
      cloudflare_name_placeholder: 'My Cloudflare',
      api_key_placeholder: 'API Key',
      zone_id_placeholder: 'Zone ID (required for Cloudflare etc.)',
      api_key_update_placeholder: 'API Key (leave empty to not update)'
    },
    notifications: {
      title_placeholder: 'Enter notification title',
      message_placeholder: 'Enter notification message'
    },
    settings: {
      save_success: 'All settings saved successfully',
      save_failed: 'Save failed',
      reset_success: 'Settings reset',
      admin_prefix_change_success: 'Admin Prefix changed successfully',
      admin_prefix_change_failed: 'Admin Prefix change failed',
      admin_prefix_changed: 'Admin panel prefix changed to',
      notification_sent: 'Notification sent',
      basic_config_load_failed: 'Failed to load basic configuration',
      notification_config_load_failed: 'Failed to load notification configuration',
      basic_config_save_failed: 'Basic settings save failed',
      notification_config_save_failed: 'Notification settings save failed',
      select_min_notification_level: 'Select minimum notification level',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx or https://qyapi.weixin.qq.com/xxx'
    }
  },
  'de-de': {
    common: { creating: 'Erstellen...', saving: 'Speichern...' },
    proxy: {
      username: 'Benutzername', password: 'Passwort',
      performance_monitoring: 'Leistungsüberwachung',
      enable_tracing: 'Anforderungsverfolgung aktivieren',
      enable_metrics: 'Metriksammlung aktivieren',
      tracing_warning: '⚠️ Die Aktivierung erhöht die CPU-Auslastung erheblich, nur für Debugging empfohlen',
      metrics_warning: '⚠️ Die Aktivierung erhöht die CPU-Auslastung, nur für Überwachung empfohlen'
    },
    sites: { edit: 'Bearbeiten', delete: 'Löschen' },
    dns: {
      cloudflare_name_placeholder: 'Mein Cloudflare',
      api_key_placeholder: 'API-Schlüssel',
      zone_id_placeholder: 'Zone ID (für Cloudflare usw. erforderlich)',
      api_key_update_placeholder: 'API-Schlüssel (leer lassen, um nicht zu aktualisieren)'
    },
    notifications: {
      title_placeholder: 'Benachrichtigungstitel eingeben',
      message_placeholder: 'Benachrichtigungsnachricht eingeben'
    },
    settings: {
      save_success: 'Alle Einstellungen erfolgreich gespeichert',
      save_failed: 'Speichern fehlgeschlagen',
      reset_success: 'Einstellungen zurückgesetzt',
      admin_prefix_change_success: 'Admin-Präfix erfolgreich geändert',
      admin_prefix_change_failed: 'Admin-Präfix-Änderung fehlgeschlagen',
      admin_prefix_changed: 'Admin-Panel-Präfix geändert zu',
      notification_sent: 'Benachrichtigung gesendet',
      basic_config_load_failed: 'Grundkonfiguration konnte nicht geladen werden',
      notification_config_load_failed: 'Benachrichtigungskonfiguration konnte nicht geladen werden',
      basic_config_save_failed: 'Speichern der Grundeinstellungen fehlgeschlagen',
      notification_config_save_failed: 'Speichern der Benachrichtigungseinstellungen fehlgeschlagen',
      select_min_notification_level: 'Mindestbenachrichtigungsstufe auswählen',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx oder https://qyapi.weixin.qq.com/xxx'
    }
  },
  'es-es': {
    common: { creating: 'Creando...', saving: 'Guardando...' },
    proxy: {
      username: 'Usuario', password: 'Contraseña',
      performance_monitoring: 'Monitoreo de rendimiento',
      enable_tracing: 'Habilitar rastreo de solicitudes',
      enable_metrics: 'Habilitar recopilación de métricas',
      tracing_warning: '⚠️ Habilitar aumentará significativamente el uso de CPU, recomendado solo para depuración',
      metrics_warning: '⚠️ Habilitar aumentará el uso de CPU, recomendado solo para monitoreo'
    },
    sites: { edit: 'Editar', delete: 'Eliminar' },
    dns: {
      cloudflare_name_placeholder: 'Mi Cloudflare',
      api_key_placeholder: 'Clave API',
      zone_id_placeholder: 'ID de zona (requerido para Cloudflare, etc.)',
      api_key_update_placeholder: 'Clave API (dejar vacío para no actualizar)'
    },
    notifications: {
      title_placeholder: 'Ingrese título de notificación',
      message_placeholder: 'Ingrese mensaje de notificación'
    },
    settings: {
      save_success: 'Todas las configuraciones guardadas exitosamente',
      save_failed: 'Guardado fallido',
      reset_success: 'Configuraciones restablecidas',
      admin_prefix_change_success: 'Prefijo de administrador cambiado exitosamente',
      admin_prefix_change_failed: 'Cambio de prefijo de administrador fallido',
      admin_prefix_changed: 'Prefijo del panel de administración cambiado a',
      notification_sent: 'Notificación enviada',
      basic_config_load_failed: 'Error al cargar configuración básica',
      notification_config_load_failed: 'Error al cargar configuración de notificaciones',
      basic_config_save_failed: 'Error al guardar configuración básica',
      notification_config_save_failed: 'Error al guardar configuración de notificaciones',
      select_min_notification_level: 'Seleccionar nivel mínimo de notificación',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx o https://qyapi.weixin.qq.com/xxx'
    }
  },
  'fr-fr': {
    common: { creating: 'Création...', saving: 'Enregistrement...' },
    proxy: {
      username: 'Nom d\'utilisateur', password: 'Mot de passe',
      performance_monitoring: 'Surveillance des performances',
      enable_tracing: 'Activer le traçage des requêtes',
      enable_metrics: 'Activer la collecte de métriques',
      tracing_warning: '⚠️ L\'activation augmentera considérablement l\'utilisation du CPU, recommandé uniquement pour le débogage',
      metrics_warning: '⚠️ L\'activation augmentera l\'utilisation du CPU, recommandé uniquement pour la surveillance'
    },
    sites: { edit: 'Modifier', delete: 'Supprimer' },
    dns: {
      cloudflare_name_placeholder: 'Mon Cloudflare',
      api_key_placeholder: 'Clé API',
      zone_id_placeholder: 'ID de zone (requis pour Cloudflare, etc.)',
      api_key_update_placeholder: 'Clé API (laisser vide pour ne pas mettre à jour)'
    },
    notifications: {
      title_placeholder: 'Entrez le titre de la notification',
      message_placeholder: 'Entrez le message de notification'
    },
    settings: {
      save_success: 'Tous les paramètres enregistrés avec succès',
      save_failed: 'Échec de l\'enregistrement',
      reset_success: 'Paramètres réinitialisés',
      admin_prefix_change_success: 'Préfixe d\'administration modifié avec succès',
      admin_prefix_change_failed: 'Échec de la modification du préfixe d\'administration',
      admin_prefix_changed: 'Préfixe du panneau d\'administration modifié en',
      notification_sent: 'Notification envoyée',
      basic_config_load_failed: 'Échec du chargement de la configuration de base',
      notification_config_load_failed: 'Échec du chargement de la configuration des notifications',
      basic_config_save_failed: 'Échec de l\'enregistrement de la configuration de base',
      notification_config_save_failed: 'Échec de l\'enregistrement de la configuration des notifications',
      select_min_notification_level: 'Sélectionner le niveau de notification minimum',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx ou https://qyapi.weixin.qq.com/xxx'
    }
  },
  'ja-jp': {
    common: { creating: '作成中...', saving: '保存中...' },
    proxy: {
      username: 'ユーザー名', password: 'パスワード',
      performance_monitoring: 'パフォーマンス監視',
      enable_tracing: 'リクエストトレースを有効化',
      enable_metrics: 'メトリクス収集を有効化',
      tracing_warning: '⚠️ 有効にするとCPU使用率が大幅に増加します。デバッグ時のみ推奨',
      metrics_warning: '⚠️ 有効にするとCPU使用率が増加します。監視時のみ推奨'
    },
    sites: { edit: '編集', delete: '削除' },
    dns: {
      cloudflare_name_placeholder: 'マイCloudflare',
      api_key_placeholder: 'APIキー',
      zone_id_placeholder: 'ゾーンID（Cloudflareなどで必要）',
      api_key_update_placeholder: 'APIキー（空欄で更新しない）'
    },
    notifications: {
      title_placeholder: '通知タイトルを入力',
      message_placeholder: '通知メッセージを入力'
    },
    settings: {
      save_success: 'すべての設定が正常に保存されました',
      save_failed: '保存に失敗しました',
      reset_success: '設定がリセットされました',
      admin_prefix_change_success: '管理プレフィックスが正常に変更されました',
      admin_prefix_change_failed: '管理プレフィックスの変更に失敗しました',
      admin_prefix_changed: '管理パネルのプレフィックスが変更されました',
      notification_sent: '通知が送信されました',
      basic_config_load_failed: '基本設定の読み込みに失敗しました',
      notification_config_load_failed: '通知設定の読み込みに失敗しました',
      basic_config_save_failed: '基本設定の保存に失敗しました',
      notification_config_save_failed: '通知設定の保存に失敗しました',
      select_min_notification_level: '最小通知レベルを選択',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx または https://qyapi.weixin.qq.com/xxx'
    }
  },
  'ko-kr': {
    common: { creating: '생성 중...', saving: '저장 중...' },
    proxy: {
      username: '사용자 이름', password: '비밀번호',
      performance_monitoring: '성능 모니터링',
      enable_tracing: '요청 추적 활성화',
      enable_metrics: '메트릭 수집 활성화',
      tracing_warning: '⚠️ 활성화하면 CPU 사용량이 크게 증가합니다. 디버깅 시에만 권장',
      metrics_warning: '⚠️ 활성화하면 CPU 사용량이 증가합니다. 모니터링 시에만 권장'
    },
    sites: { edit: '편집', delete: '삭제' },
    dns: {
      cloudflare_name_placeholder: '내 Cloudflare',
      api_key_placeholder: 'API 키',
      zone_id_placeholder: '존 ID (Cloudflare 등에 필요)',
      api_key_update_placeholder: 'API 키 (비워두면 업데이트하지 않음)'
    },
    notifications: {
      title_placeholder: '알림 제목 입력',
      message_placeholder: '알림 메시지 입력'
    },
    settings: {
      save_success: '모든 설정이 성공적으로 저장되었습니다',
      save_failed: '저장 실패',
      reset_success: '설정이 재설정되었습니다',
      admin_prefix_change_success: '관리자 접두사가 성공적으로 변경되었습니다',
      admin_prefix_change_failed: '관리자 접두사 변경 실패',
      admin_prefix_changed: '관리 패널 접두사가 다음으로 변경됨',
      notification_sent: '알림이 전송되었습니다',
      basic_config_load_failed: '기본 구성 로드 실패',
      notification_config_load_failed: '알림 구성 로드 실패',
      basic_config_save_failed: '기본 설정 저장 실패',
      notification_config_save_failed: '알림 설정 저장 실패',
      select_min_notification_level: '최소 알림 수준 선택',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx 또는 https://qyapi.weixin.qq.com/xxx'
    }
  },
  'ru-ru': {
    common: { creating: 'Создание...', saving: 'Сохранение...' },
    proxy: {
      username: 'Имя пользователя', password: 'Пароль',
      performance_monitoring: 'Мониторинг производительности',
      enable_tracing: 'Включить трассировку запросов',
      enable_metrics: 'Включить сбор метрик',
      tracing_warning: '⚠️ Включение значительно увеличит использование ЦП, рекомендуется только для отладки',
      metrics_warning: '⚠️ Включение увеличит использование ЦП, рекомендуется только для мониторинга'
    },
    sites: { edit: 'Редактировать', delete: 'Удалить' },
    dns: {
      cloudflare_name_placeholder: 'Мой Cloudflare',
      api_key_placeholder: 'API ключ',
      zone_id_placeholder: 'ID зоны (требуется для Cloudflare и т.д.)',
      api_key_update_placeholder: 'API ключ (оставьте пустым, чтобы не обновлять)'
    },
    notifications: {
      title_placeholder: 'Введите заголовок уведомления',
      message_placeholder: 'Введите сообщение уведомления'
    },
    settings: {
      save_success: 'Все настройки успешно сохранены',
      save_failed: 'Сохранение не удалось',
      reset_success: 'Настройки сброшены',
      admin_prefix_change_success: 'Префикс администратора успешно изменен',
      admin_prefix_change_failed: 'Не удалось изменить префикс администратора',
      admin_prefix_changed: 'Префикс панели администратора изменен на',
      notification_sent: 'Уведомление отправлено',
      basic_config_load_failed: 'Не удалось загрузить базовую конфигурацию',
      notification_config_load_failed: 'Не удалось загрузить конфигурацию уведомлений',
      basic_config_save_failed: 'Не удалось сохранить базовые настройки',
      notification_config_save_failed: 'Не удалось сохранить настройки уведомлений',
      select_min_notification_level: 'Выбрать минимальный уровень уведомлений',
      webhook_placeholder: 'https://hooks.slack.com/services/xxx или https://qyapi.weixin.qq.com/xxx'
    }
  }
};

function updateTSFile(filePath, lang) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const data = translations[lang];
    
    if (!data) {
      console.log(`No translation data for ${lang}`);
      return;
    }
    
    let modified = false;
    
    // 更新每个部分
    Object.keys(data).forEach(section => {
      const sectionData = data[section];
      Object.keys(sectionData).forEach(key => {
        const value = sectionData[key].replace(/'/g, "\\'");
        
        // 检查是否已存在
        const keyPattern = new RegExp(`${key}:\\s*['"']`, 'g');
        if (!keyPattern.test(content)) {
          // 找到对应section的结束位置并添加
          const sectionPattern = new RegExp(`(${section}:\\s*\\{[\\s\\S]*?)(\\n\\s*\\},)`, 'g');
          const match = sectionPattern.exec(content);
          if (match) {
            const insertion = `    ${key}: '${value}',\n`;
            content = content.replace(sectionPattern, `$1\n${insertion}$2`);
            modified = true;
          }
        }
      });
    });
    
    if (modified) {
      fs.writeFileSync(filePath, content);
      console.log(`✓ Updated ${filePath}`);
    } else {
      console.log(`  Already up-to-date: ${filePath}`);
    }
  } catch (error) {
    console.error(`✗ Error updating ${filePath}:`, error.message);
  }
}

// 更新所有语言文件
const languages = ['en-us', 'de-de', 'es-es', 'fr-fr', 'ja-jp', 'ko-kr', 'ru-ru'];

console.log('Updating frontend language files...\n');

languages.forEach(lang => {
  const filePath = path.join(__dirname, '..', 'frontend', 'src', 'i18n', 'languages', `${lang}.ts`);
  if (fs.existsSync(filePath)) {
    updateTSFile(filePath, lang);
  } else {
    console.log(`  File not found: ${filePath}`);
  }
});

console.log('\n✓ All language files processed!');
