/// تنظيف النص الخارج من محرك قراءة الصور (OCR) قبل عرضه للمستخدم أو تحليله.
///
/// دالة نقية (بدون أي مكتبات) عشان تتختبر بسهولة:
/// - توحيد نهايات الأسطر.
/// - شيل محارف التحكم اللي بيرجّعها Tesseract (زي فاصل الصفحة \f).
/// - شيل المسافات الزايدة في آخر كل سطر.
/// - دمج الأسطر الفاضية المتتالية في سطر فاضي واحد.
String cleanOcrText(String raw) {
  var s = raw.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  // محارف التحكم (ما عدا \n و \t)
  s = s.replaceAll(RegExp(r'[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]'), '');
  final lines = s.split('\n').map((l) => l.replaceAll(RegExp(r'[ \t ]+$'), ''));
  final out = <String>[];
  var blank = 0;
  for (final l in lines) {
    if (l.trim().isEmpty) {
      blank++;
      if (blank > 1) continue;
      out.add('');
    } else {
      blank = 0;
      out.add(l);
    }
  }
  return out.join('\n').trim();
}
