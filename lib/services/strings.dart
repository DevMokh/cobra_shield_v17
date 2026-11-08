import '../core/models.dart';
import 'settings_store.dart';

/// طبقة ترجمة خفيفة لواجهة التطبيق (عربي/إنجليزي).
///
/// نطاق هذا الإصدار: شريط التنقل، عناوين الشاشات، ومستوى/نصيحة نتيجة الفحص.
/// النصوص التفصيلية (شرح كل مؤشر، سيناريوهات التدريب، التقرير المنسوخ) تفضل
/// عربي في هذا الإصدار لتجنّب مضاعفة كل نص تحليل بدون اختبار حقيقي.
enum S {
  navHome, navLink, navMessage, navTrain, navTools, navHistory, navMore,
  homeTitle, homeSubtitle,
  urlTitle, urlSubtitle,
  msgTitle, msgSubtitle,
  trainTitle, trainSubtitle,
  toolsTitle, toolsSubtitle,
  historyTitle, historySubtitle,
  learnTitle, learnSubtitle,
  moreTitle, moreSubtitle,
  levelLow, levelMedium, levelHigh, levelCritical,
  adviceLow, adviceMedium, adviceHigh, adviceCritical,
  verdictConfirmed, adviceConfirmed, verdictInsufficient, adviceInsufficient,
  copyReport, languageLabel, languageHint,
}

const Map<S, String> _ar = <S, String>{
  S.navHome: 'الرئيسية',
  S.navLink: 'رابط',
  S.navMessage: 'رسالة',
  S.navTrain: 'تدرّب',
  S.navTools: 'أدوات',
  S.navHistory: 'السجل',
  S.navMore: 'المزيد',
  S.homeTitle: 'Cobra Shield',
  S.homeSubtitle: 'درعك ضد التصيّد والروابط المشبوهة',
  S.urlTitle: 'Cobra Shield',
  S.urlSubtitle: 'افحص الرابط قبل ما تفتحه',
  S.msgTitle: 'كشف رسائل التصيّد',
  S.msgSubtitle: 'حلّل الرسالة والروابط داخلها',
  S.trainTitle: 'تدرّب على الكشف',
  S.trainSubtitle: 'خمس مراحل تتصاعد في الصعوبة',
  S.toolsTitle: 'أدوات الأمان',
  S.toolsSubtitle: 'كلمات السر والروابط والمرسل والفحص المجمّع',
  S.historyTitle: 'سجل الفحوصات',
  S.historySubtitle: 'محفوظ على جهازك فقط',
  S.learnTitle: 'تعلّم الحماية',
  S.learnSubtitle: 'قواعد سريعة تحميك من الاحتيال',
  S.moreTitle: 'المزيد',
  S.moreSubtitle: 'فحوصات إضافية وتعلّم وأدوات وإعدادات',
  S.levelLow: 'لا مؤشرات واضحة',
  S.levelMedium: 'مشبوه',
  S.levelHigh: 'خطير',
  S.levelCritical: 'احتيال مرجّح',
  S.adviceLow:
      'لم نجد علامات خطر واضحة، لكن هذا لا يعني أنه آمن 100%. افتحه فقط لو كنت تتوقعه من مصدر موثوق.',
  S.adviceMedium:
      'فيه علامات تستدعي الحذر. لا تُدخل أي بيانات أو أكواد، وتأكد من المصدر أولًا.',
  S.adviceHigh: 'علامات قوية على التصيّد. الأفضل ألا تفتحه، ولا تدخل أي بيانات.',
  S.adviceCritical:
      'يشبه الاحتيال بدرجة كبيرة. لا تفتحه، لا ترد، واحذف الرسالة أو أبلغ عنها.',
  S.verdictConfirmed: 'تهديد مؤكد',
  S.adviceConfirmed:
      'مصدر موثوق صنّف هذا المحتوى كتهديد. لا تفتحه ولا تدخل أي بيانات، واحذف الرسالة أو أبلغ عنها.',
  S.verdictInsufficient: 'معلومات غير كافية',
  S.adviceInsufficient:
      'الفحص لم يكتمل (مصدر فشل أو جزء من المحتوى لم يُفحص)، فلا نستطيع القول إنه بلا مؤشرات. تعامل معه بحذر وراجع تفاصيل النتيجة.',
  S.copyReport: 'نسخ التقرير',
  S.languageLabel: 'لغة الواجهة',
  S.languageHint:
      'يترجم شريط التنقل وعناوين الشاشات ونتيجة الفحص. شرح المؤشرات التفصيلي والتدريب يفضلوا عربي حاليًا.',
};

const Map<S, String> _en = <S, String>{
  S.navHome: 'Home',
  S.navLink: 'Link',
  S.navMessage: 'Message',
  S.navTrain: 'Train',
  S.navTools: 'Tools',
  S.navHistory: 'History',
  S.navMore: 'More',
  S.homeTitle: 'Cobra Shield',
  S.homeSubtitle: 'Your shield against phishing and suspicious links',
  S.urlTitle: 'Cobra Shield',
  S.urlSubtitle: 'Scan a link before you open it',
  S.msgTitle: 'Phishing Message Detector',
  S.msgSubtitle: 'Analyze the message and the links inside it',
  S.trainTitle: 'Practice Detection',
  S.trainSubtitle: 'Five levels of rising difficulty',
  S.toolsTitle: 'Security Tools',
  S.toolsSubtitle: 'Passwords, link cleanup, sender check and batch scan',
  S.historyTitle: 'Scan History',
  S.historySubtitle: 'Saved on your device only',
  S.learnTitle: 'Learn to Protect Yourself',
  S.learnSubtitle: 'Quick rules that protect you from scams',
  S.moreTitle: 'More',
  S.moreSubtitle: 'Extra scans, learning, tools and settings',
  S.levelLow: 'No clear indicators',
  S.levelMedium: 'Suspicious',
  S.levelHigh: 'Dangerous',
  S.levelCritical: 'Likely scam',
  S.adviceLow:
      "We didn't find clear danger signs, but that doesn't mean it's 100% safe. Only open it if you expect it from a source you trust.",
  S.adviceMedium:
      'There are signs that call for caution. Do not enter any data or codes, and verify the source first.',
  S.adviceHigh:
      "Strong signs of phishing. It's best not to open it, and don't enter any data.",
  S.adviceCritical:
      'This strongly resembles a scam. Do not open it, do not reply, and delete or report the message.',
  S.verdictConfirmed: 'Confirmed threat',
  S.adviceConfirmed:
      'A trusted source flagged this as a threat. Do not open it or enter any data, and delete or report the message.',
  S.verdictInsufficient: 'Not enough information',
  S.adviceInsufficient:
      'The scan did not complete (a source failed or part of the content was not checked), so we cannot say there are no indicators. Be careful and review the details.',
  S.copyReport: 'Copy report',
  S.languageLabel: 'Interface language',
  S.languageHint:
      'Translates the nav bar, screen headers and the scan verdict. Detailed finding explanations and training stay in Arabic for now.',
};

String tr(S key) => (SettingsStore.instance.english ? _en : _ar)[key] ?? '';

S levelLabelKey(RiskLevel l) {
  switch (l) {
    case RiskLevel.low:
      return S.levelLow;
    case RiskLevel.medium:
      return S.levelMedium;
    case RiskLevel.high:
      return S.levelHigh;
    case RiskLevel.critical:
      return S.levelCritical;
  }
}

/// مفتاح عنوان الحكم النهائي (بيدمج المستوى التفصيلي لو الحكم "مشبوه").
S verdictLabelKey(ScanResult r) {
  switch (r.verdict) {
    case Verdict.confirmedThreat:
      return S.verdictConfirmed;
    case Verdict.insufficient:
      return S.verdictInsufficient;
    case Verdict.suspicious:
    case Verdict.noIndicators:
      return levelLabelKey(r.level);
  }
}

S verdictAdviceKey(ScanResult r) {
  switch (r.verdict) {
    case Verdict.confirmedThreat:
      return S.adviceConfirmed;
    case Verdict.insufficient:
      return S.adviceInsufficient;
    case Verdict.suspicious:
    case Verdict.noIndicators:
      return levelAdviceKey(r.level);
  }
}

S levelAdviceKey(RiskLevel l) {
  switch (l) {
    case RiskLevel.low:
      return S.adviceLow;
    case RiskLevel.medium:
      return S.adviceMedium;
    case RiskLevel.high:
      return S.adviceHigh;
    case RiskLevel.critical:
      return S.adviceCritical;
  }
}
