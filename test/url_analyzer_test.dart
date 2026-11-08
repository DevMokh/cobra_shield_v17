import 'package:flutter_test/flutter_test.dart';

import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/url_analyzer.dart';
import 'package:cobra_shield/services/url_report.dart';

// اختبارات المحلل: روابط معروفة بأنها احتيال لازم تتصنف "متوسط" أو أعلى،
// وروابط سليمة معروفة لازم تفضل "منخفض". لو غيرت القواعد وفشل اختبار،
// يبقى التعديل كسر حالة قديمة.
void main() {
  group('روابط مشبوهة', () {
    const suspicious = <String>[
    'https://evil-site.com/paypal/login',
    'https://xkqzrtvbnmpl.top/a',
    'https://a8392kd04x1zq.com/verify',
    'http://win-prize-now.top/claim',
    'http://vodafone-egypt.update-line.xyz',
    'http://parcel-fee-check.click/pay',
    'https://paypal.com.account-verify.xyz/login',
    'https://paypa1.com/signin',
    'https://traffic-pay.top/fine',
    'https://secure-amazon.eg.login-check.com/ap/signin',
    'https://www.arnazon.com/orders',
    'https://sites.google.com/view/bank-login-update',
    'https://mail.google.com@evil-login.com/inbox',
    'http://nbe-secure-login.top/verify',
    'https://google.pw/login',
    'https://аpple.com/id',
    'https://dhl-parcel-redelivery.top/pay',
    'https://noon-verify-account.xyz/login',
    ];
    for (final u in suspicious) {
      test(u, () {
        final r = UrlAnalyzer.analyze(u);
        expect(r.level, isNot(RiskLevel.low), reason: 'score=${r.score}');
      });
    }
  });

  group('روابط سليمة', () {
    const legit = <String>[
    'https://www.bbc.com/news/facebook-account-changes',
    'https://www.theguardian.com/technology/amazon-prime-day',
    'https://medium.com/@x/why-paypal-won',
    'https://ar.wikipedia.org/wiki/مصر',
    'https://www.amazon.eg/gp/help/customer/display.html',
    'https://support.apple.com/ar-eg',
    'https://www.google.com',
    'https://www.google.de/search?q=x',
    'https://amazon.co.uk/orders',
    'https://apple-pie-recipes.com/best',
    'https://orange-juice-shop.com',
    'https://accounts.google.com/signin/v2',
    'https://www.paypal.com/myaccount/summary',
    'https://www.facebook.com/login',
    'https://www.microsoft.com/en-us/security',
    'https://news.ycombinator.com/item?id=1',
    'https://stackoverflow.com/questions/1',
    'https://dhl.de/track',
    'https://www.noon.com/egypt-ar/',
    'https://zoom.us/j/123',
    ];
    for (final u in legit) {
      test(u, () {
        final r = UrlAnalyzer.analyze(u);
        expect(r.level, RiskLevel.low, reason: 'score=${r.score}');
      });
    }
  });

  test('رابط جافاسكربت خطير', () {
    final r = UrlAnalyzer.analyze('javascript:alert(1)');
    expect(r.level, isNot(RiskLevel.low));
  });

  test('نص فاضي', () {
    final r = UrlAnalyzer.analyze('   ');
    expect(r.score, 0);
  });

  // -------------------------------------------------------------------
  // محرك التطبيع وكشف التمويه (v1.10)
  // -------------------------------------------------------------------

  group('تمويه وتهرّب (لازم يبان)', () {
    // [الرابط، أقل مستوى مقبول]
    final evasive = <List<Object>>[
      <Object>['http://0x7f000001/login', RiskLevel.high],
      <Object>['http://3232235777/', RiskLevel.high],
      <Object>['http://0177.0.0.1/', RiskLevel.high],
      <Object>['http://[::1]/admin', RiskLevel.high],
      <Object>['https://8.8.8.8/login', RiskLevel.medium],
      <Object>['http://user:pass@192.168.1.1/admin', RiskLevel.critical],
      <Object>['https://paypal.com%2F@evil.com/login', RiskLevel.high],
      <Object>['https://evil.com\\@google.com/x', RiskLevel.medium],
      <Object>['https://@evil.com', RiskLevel.medium],
      <Object>['https://goo​gle.com/login', RiskLevel.medium],
      <Object>['http://exa%0Ample.com/', RiskLevel.high],
      <Object>['https://xn--80ak6aa92e.com', RiskLevel.high],
      <Object>['https://аррӏе.com', RiskLevel.high],
      <Object>['https://paypàl.com/login', RiskLevel.critical],
      <Object>['hxxps://paypal-login[.]xyz/verify', RiskLevel.high],
      <Object>['https://paypal.com∕evil.com/login', RiskLevel.critical],
      <Object>['javascript:alert(1)', RiskLevel.critical],
      <Object>['java\nscript:alert(1)', RiskLevel.critical],
      <Object>['JaVaScRiPt:alert(1)', RiskLevel.critical],
      <Object>['javascript%3Aalert(1)', RiskLevel.critical],
    ];
    for (final e in evasive) {
      final u = e[0] as String;
      final min = e[1] as RiskLevel;
      test(u.replaceAll('\n', r'\n'), () {
        final r = UrlAnalyzer.analyze(u);
        expect(r.level.index, greaterThanOrEqualTo(min.index),
            reason: 'score=${r.score} ${r.findings.map((f) => f.code).toList()}');
        expect(r.findings.any((f) => f.code == 'analysis_failed'), isFalse);
      });
    }
  });

  group('روابط دولية سليمة (لا إنذار)', () {
    const legitIdn = <String>[
      'https://münchen.de/',
      'https://مصر.eg/',
      'https://www.google.com/url?q=https%3A%2F%2Fexample.com%2F',
      'https://ar.wikipedia.org/wiki/%D9%85%D8%B5%D8%B1',
    ];
    for (final u in legitIdn) {
      test(u, () {
        final r = UrlAnalyzer.analyze(u);
        expect(r.level, RiskLevel.low, reason: 'score=${r.score}');
        expect(r.findings.any((f) => f.code == 'analysis_failed'), isFalse);
      });
    }
  });

  test('الفشل الداخلي مش بيتحسب آمن: كل الأمثلة القديمة بدون analysis_failed', () {
    const all = <String>[
      'https://www.google.com',
      'https://evil-site.com/paypal/login',
      'https://аpple.com/id',
      'https://mail.google.com@evil-login.com/inbox',
    ];
    for (final u in all) {
      expect(UrlAnalyzer.analyze(u).findings.any((f) => f.code == 'analysis_failed'),
          isFalse,
          reason: u);
    }
  });

  group('أوزان المحرك', () {
    int w(String url, String code) {
      final r = UrlAnalyzer.analyze(url);
      final hits = r.findings.where((f) => f.code == code).toList();
      expect(hits, isNotEmpty, reason: '$url -> ${r.findings.map((f) => f.code).toList()}');
      return hits.first.points;
    }

    test('IP مباشر +30', () => expect(w('https://8.8.8.8/', 'ip_host'), 30));
    test('IP مموّه +35', () => expect(w('https://0x08080808/', 'ip_obfuscated'), 35));
    test('@ +35', () => expect(w('https://a@evil.com/', 'userinfo_at'), 35));
    test('Homograph +25', () => expect(w('https://аpple.com/', 'homograph'), 25));
    test('مستويات فرعية كثيرة +15', () {
      expect(w('https://a.b.c.d.e.evil.com/', 'many_subdomains'), 15);
    });
    test('كلمات حساسة كثيرة +15', () {
      expect(w('https://evil.com/login/verify/account/update', 'keyword_stuffing'), 15);
    });
  });

  group('التقرير المنظم', () {
    test('بنية التقرير', () {
      final rep = UrlAnalyzer.report('http://0x7f000001/login');
      expect(rep.tier, ThreatTier.dangerous);
      expect(rep.cleanUrl, 'http://127.0.0.1/login');
      expect(rep.valid, isTrue);
      expect(rep.score, lessThanOrEqualTo(100));
      expect(rep.rawScore, greaterThanOrEqualTo(rep.score));
      final f = rep.flags.firstWhere((x) => x.code == 'ip_obfuscated');
      expect(f.weight, 35);
      expect(f.explanation, contains('127.0.0.1'));
      expect(f.title, isNotEmpty);
    });

    test('JSON', () {
      final j = UrlAnalyzer.report('https://paypal.com%2F@evil.com/login').toJson();
      expect(j['tier'], 'dangerous');
      expect(j['clean_url'], contains('evil.com'));
      final flags = j['flags'] as List<Object?>;
      expect(flags, isNotEmpty);
      final first = flags.first as Map<String, Object?>;
      expect(first.keys, containsAll(<String>['code', 'severity', 'title', 'explanation', 'weight']));
    });

    test('رابط مكسور: غير صالح بس ما بيرميش استثناء', () {
      for (final u in <String>['https://', 'http://exa<mple.com', 'http://a.com:99999', 'http://[::1']) {
        final rep = UrlAnalyzer.report(u);
        expect(rep.valid, isFalse, reason: u);
        expect(rep.flags.any((x) => x.code == 'invalid_url'), isTrue, reason: u);
        expect(rep.tier, isNot(ThreatTier.safe), reason: u);
      }
    });

    test('رابط نضيف: safe بدون إشارات تحذير', () {
      final rep = UrlAnalyzer.report('https://www.google.com');
      expect(rep.tier, ThreatTier.safe);
      expect(rep.flags.where((x) => x.weight > 0), isEmpty);
    });

    test('النص الفاضي', () {
      final rep = UrlAnalyzer.report('   ');
      expect(rep.score, 0);
      expect(rep.flags, isEmpty);
    });

    test('رابط ضخم بيتقطع ويتعلّم partial', () {
      final rep = UrlAnalyzer.report('https://example.com/${'a' * 6000}');
      expect(rep.partial, isTrue);
    });
  });
}
