import 'package:cobra_shield/services/ocr_text.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('cleanOcrText', () {
    test('يوحّد نهايات الأسطر', () {
      expect(cleanOcrText('a\r\nb'), 'a\nb');
      expect(cleanOcrText('l1\rl2\r\r\r\rl3'), 'l1\nl2\n\nl3');
    });

    test('يشيل فاصل الصفحة ومحارف التحكم', () {
      expect(cleanOcrText('سلام\f'), 'سلام');
      expect(cleanOcrText('a\u0001b'), 'ab');
    });

    test('يدمج الأسطر الفاضية المتتالية', () {
      expect(cleanOcrText('a  \n\n\n\nb'), 'a\n\nb');
    });

    test('يشيل المسافات في آخر السطر وحول النص', () {
      expect(cleanOcrText('\n\n  x  \n'), 'x');
      expect(cleanOcrText('رابط: http://a.com '), 'رابط: http://a.com');
    });

    test('يحافظ على التاب داخل السطر', () {
      expect(cleanOcrText('a\tb'), 'a\tb');
    });

    test('نص فاضي أو مسافات فقط يرجّع نص فاضي', () {
      expect(cleanOcrText(''), '');
      expect(cleanOcrText('   \n  \n'), '');
    });
  });
}
