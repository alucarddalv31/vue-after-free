// Language translations
// Detected locale: jsmaf.locale

var lang = {}

var detectedLocale = jsmaf.locale || 'en'
log('Detected locale: ' + detectedLocale)

switch (detectedLocale) {
  case 'es':
    // Spanish
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Menu de Payloads'
    lang.config = 'Configuracion'
    lang.exit = 'Salir'
    lang.back = 'Volver'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Auto Cerrar'
    lang.totalAttempts = 'Intentos Totales: '
    lang.successes = 'Exitos: '
    lang.failures = 'Fallos: '
    lang.successRate = 'Tasa de Exito: '
    lang.failureRate = 'Tasa de Fallo: '
    lang.loadingMainMenu = 'Cargando menu principal...'
    lang.mainMenuLoaded = 'Menu principal cargado'
    lang.loadingConfig = 'Cargando configuracion...'
    lang.configLoaded = 'Configuracion cargada'
    break
//vue doesnt have these locales in the fonts for asian and arabic languages. need to figure out how to load custom font . please reference /app0/assets/font/ for examples
  //~ case 'ar':
    //~ // Arabic
    //~ lang.jailbreak = 'Jailbreak'
    //~ lang.payloadMenu = 'قائمة الحمولات'
    //~ lang.config = 'الاعدادات'
    //~ lang.exit = 'خروج'
    //~ lang.back = 'رجوع'
    //~ lang.autoLapse = 'Auto Lapse'
    //~ lang.autoPoop = 'Auto Poop'
    //~ lang.autoClose = 'اغلاق تلقائي'
    //~ lang.totalAttempts = 'اجمالي المحاولات: '
    //~ lang.successes = 'النجاحات: '
    //~ lang.failures = 'الاخفاقات: '
    //~ lang.successRate = 'معدل النجاح: '
    //~ lang.failureRate = 'معدل الفشل: '
    //~ lang.loadingMainMenu = '...جاري تحميل القائمة الرئيسية'
    //~ lang.mainMenuLoaded = 'تم تحميل القائمة الرئيسية'
    //~ lang.loadingConfig = '...جاري تحميل الاعدادات'
    //~ lang.configLoaded = 'تم تحميل الاعدادات'
    //~ break

  //~ case 'ko':
    //~ // Korean
    //~ lang.jailbreak = '탈옥'
    //~ lang.payloadMenu = '페이로드 메뉴'
    //~ lang.config = '설정'
    //~ lang.exit = '종료'
    //~ lang.back = '뒤로'
    //~ lang.autoLapse = '자동 Lapse'
    //~ lang.autoPoop = '자동 Poop'
    //~ lang.autoClose = '자동 닫기'
    //~ lang.totalAttempts = '총 시도: '
    //~ lang.successes = '성공: '
    //~ lang.failures = '실패: '
    //~ lang.successRate = '성공률: '
    //~ lang.failureRate = '실패율: '
    //~ lang.loadingMainMenu = '메인 메뉴 로딩중...'
    //~ lang.mainMenuLoaded = '메인 메뉴 로딩 완료'
    //~ lang.loadingConfig = '설정 로딩중...'
    //~ lang.configLoaded = '설정 로딩 완료'
    //~ break

  //~ case 'ja':
    //~ // Japanese
    //~ lang.jailbreak = '脱獄'
    //~ lang.payloadMenu = 'ペイロードメニュー'
    //~ lang.config = '設定'
    //~ lang.exit = '終了'
    //~ lang.back = '戻る'
    //~ lang.autoLapse = '自動Lapse'
    //~ lang.autoPoop = '自動Poop'
    //~ lang.autoClose = '自動終了'
    //~ lang.totalAttempts = '試行回数: '
    //~ lang.successes = '成功: '
    //~ lang.failures = '失敗: '
    //~ lang.successRate = '成功率: '
    //~ lang.failureRate = '失敗率: '
    //~ lang.loadingMainMenu = 'メインメニュー読み込み中...'
    //~ lang.mainMenuLoaded = 'メインメニュー読み込み完了'
    //~ lang.loadingConfig = '設定読み込み中...'
    //~ lang.configLoaded = '設定読み込み完了'
    //~ break

  case 'pt':
    // Portuguese
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Menu de Payloads'
    lang.config = 'Configuracao'
    lang.exit = 'Sair'
    lang.back = 'Voltar'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Fechar Auto'
    lang.totalAttempts = 'Total de Tentativas: '
    lang.successes = 'Sucessos: '
    lang.failures = 'Falhas: '
    lang.successRate = 'Taxa de Sucesso: '
    lang.failureRate = 'Taxa de Falha: '
    lang.loadingMainMenu = 'Carregando menu principal...'
    lang.mainMenuLoaded = 'Menu principal carregado'
    lang.loadingConfig = 'Carregando configuracao...'
    lang.configLoaded = 'Configuracao carregada'
    break

  case 'fr':
    // French
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Menu Payload'
    lang.config = 'Configuration'
    lang.exit = 'Quitter'
    lang.back = 'Retour'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Fermer Auto'
    lang.totalAttempts = 'Tentatives Totales: '
    lang.successes = 'Succes: '
    lang.failures = 'Echecs: '
    lang.successRate = 'Taux de Succes: '
    lang.failureRate = 'Taux Echec: '
    lang.loadingMainMenu = 'Chargement du menu principal...'
    lang.mainMenuLoaded = 'Menu principal charge'
    lang.loadingConfig = 'Chargement de la configuration...'
    lang.configLoaded = 'Configuration chargee'
    break

  case 'de':
    // German
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Payload Menu'
    lang.config = 'Einstellungen'
    lang.exit = 'Beenden'
    lang.back = 'Zuruck'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Auto Schliessen'
    lang.totalAttempts = 'Gesamtversuche: '
    lang.successes = 'Erfolge: '
    lang.failures = 'Fehlschlage: '
    lang.successRate = 'Erfolgsrate: '
    lang.failureRate = 'Fehlerrate: '
    lang.loadingMainMenu = 'Hauptmenu wird geladen...'
    lang.mainMenuLoaded = 'Hauptmenu geladen'
    lang.loadingConfig = 'Einstellungen werden geladen...'
    lang.configLoaded = 'Einstellungen geladen'
    break

  case 'it':
    // Italian
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Menu Payload'
    lang.config = 'Configurazione'
    lang.exit = 'Esci'
    lang.back = 'Indietro'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Chiudi Auto'
    lang.totalAttempts = 'Tentativi Totali: '
    lang.successes = 'Successi: '
    lang.failures = 'Fallimenti: '
    lang.successRate = 'Tasso di Successo: '
    lang.failureRate = 'Tasso di Fallimento: '
    lang.loadingMainMenu = 'Caricamento menu principale...'
    lang.mainMenuLoaded = 'Menu principale caricato'
    lang.loadingConfig = 'Caricamento configurazione...'
    lang.configLoaded = 'Configurazione caricata'
    break

  case 'nl':
    // Dutch
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Payload Menu'
    lang.config = 'Instellingen'
    lang.exit = 'Afsluiten'
    lang.back = 'Terug'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Auto Sluiten'
    lang.totalAttempts = 'Totaal Pogingen: '
    lang.successes = 'Successen: '
    lang.failures = 'Mislukkingen: '
    lang.successRate = 'Succespercentage: '
    lang.failureRate = 'Faalpercentage: '
    lang.loadingMainMenu = 'Hoofdmenu laden...'
    lang.mainMenuLoaded = 'Hoofdmenu geladen'
    lang.loadingConfig = 'Instellingen laden...'
    lang.configLoaded = 'Instellingen geladen'
    break

  case 'pl':
    // Polish
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Menu Payload'
    lang.config = 'Konfiguracja'
    lang.exit = 'Wyjscie'
    lang.back = 'Wstecz'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Auto Zamknij'
    lang.totalAttempts = 'Laczna Liczba Prob: '
    lang.successes = 'Sukcesy: '
    lang.failures = 'Niepowodzenia: '
    lang.successRate = 'Wskaznik Sukcesu: '
    lang.failureRate = 'Wskaznik Bledow: '
    lang.loadingMainMenu = 'Ladowanie menu glownego...'
    lang.mainMenuLoaded = 'Menu glowne zaladowane'
    lang.loadingConfig = 'Ladowanie konfiguracji...'
    lang.configLoaded = 'Konfiguracja zaladowana'
    break

  case 'tr':
    // Turkish
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Payload Menusu'
    lang.config = 'Ayarlar'
    lang.exit = 'Cikis'
    lang.back = 'Geri'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Otomatik Kapat'
    lang.totalAttempts = 'Toplam Deneme: '
    lang.successes = 'Basarilar: '
    lang.failures = 'Basarisizliklar: '
    lang.successRate = 'Basari Orani: '
    lang.failureRate = 'Basarisizlik Orani: '
    lang.loadingMainMenu = 'Ana menu yukleniyor...'
    lang.mainMenuLoaded = 'Ana menu yuklendi'
    lang.loadingConfig = 'Ayarlar yukleniyor...'
    lang.configLoaded = 'Ayarlar yuklendi'
    break

  case 'en':
  default:
    // English (default)
    lang.jailbreak = 'Jailbreak'
    lang.payloadMenu = 'Payload Menu'
    lang.config = 'Config'
    lang.exit = 'Exit'
    lang.back = 'Back'
    lang.autoLapse = 'Auto Lapse'
    lang.autoPoop = 'Auto Poop'
    lang.autoClose = 'Auto Close'
    lang.totalAttempts = 'Total Attempts: '
    lang.successes = 'Successes: '
    lang.failures = 'Failures: '
    lang.successRate = 'Success Rate: '
    lang.failureRate = 'Failure Rate: '
    lang.loadingMainMenu = 'Loading main menu...'
    lang.mainMenuLoaded = 'Main menu loaded'
    lang.loadingConfig = 'Loading config UI...'
    lang.configLoaded = 'Config UI loaded'
    break
}

log('Language loaded: ' + detectedLocale)
