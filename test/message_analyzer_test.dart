import 'package:flutter_test/flutter_test.dart';

import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/message_analyzer.dart';

void main() {
  group('استخراج الروابط', () {
    test('رابط كامل بنقطة في آخر الجملة', () {
      final l = MessageAnalyzer.extractLinks(
          'عاجل: اضغط http://nbe-secure-login.top/verify.');
      expect(l, ['http://nbe-secure-login.top/verify']);
    });

    test('رابط مختصر من غير http', () {
      final l = MessageAnalyzer.extractLinks('مبروك! اضغط هنا: bit.ly/3xYz12 الآن');
      expect(l, ['bit.ly/3xYz12']);
    });

    test('إيميل مش رابط', () {
      expect(MessageAnalyzer.extractLinks('راسلنا على info@example.com للدعم'),
          isEmpty);
    });

    test('مفيش روابط', () {
      expect(MessageAnalyzer.extractLinks('لا يوجد رابط هنا'), isEmpty);
    });
  });

  group('تحليل الرسائل', () {
    test('رسالة نصب واضحة: جائزة + استعجال + رابط مشبوه', () {
      final r = MessageAnalyzer.analyze(
          'مبروك! فزت بجائزة كبيرة. اضغط الآن خلال 24 ساعة وادفع الرسوم '
          'http://win-prize-now.top/claim');
      expect(r.level, isNot(RiskLevel.low), reason: 'score=${r.score}');
    });

    test('رسالة عادية', () {
      final r = MessageAnalyzer.analyze('هنتقابل الساعة خمسة في الكافيه');
      expect(r.level, RiskLevel.low, reason: 'score=${r.score}');
    });
  });

  group('الفحص الجزئي (حدود الطول والروابط)', () {
    bool hasTitle(ScanResult r, String part) =>
        r.findings.any((f) => f.title.contains(part));

    test('رسالة طويلة جدًا: تحذير إن الباقي ما اتفحصش', () {
      final r = MessageAnalyzer.analyze('مرحبا ' * 1200);
      expect(hasTitle(r, 'الرسالة طويلة'), isTrue);
    });

    test('رسالة عادية: مفيش تحذير حدود', () {
      final r = MessageAnalyzer.analyze('هنتقابل الساعة خمسة في الكافيه');
      expect(hasTitle(r, 'الرسالة طويلة'), isFalse);
      expect(hasTitle(r, 'روابط أكتر'), isFalse);
    });

    test('أكتر من 8 روابط: تحذير، والمفحوص 8 بس', () {
      final text = List<String>.generate(10, (i) => 'https://site$i.example.com/p').join(' ');
      final r = MessageAnalyzer.analyze(text);
      expect(r.links.length, MessageAnalyzer.maxLinks);
      expect(hasTitle(r, 'روابط أكتر'), isTrue);
    });

    test('8 روابط بالظبط: مفيش تحذير', () {
      final text = List<String>.generate(8, (i) => 'https://site$i.example.com/p').join(' ');
      final r = MessageAnalyzer.analyze(text);
      expect(r.links.length, 8);
      expect(hasTitle(r, 'روابط أكتر'), isFalse);
    });
  });
}
