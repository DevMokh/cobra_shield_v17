import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/http_util.dart';
import 'package:cobra_shield/services/online_intel.dart';
import 'package:cobra_shield/services/threat_feed.dart';
import 'package:flutter_test/flutter_test.dart';

const String _key = 'SECRET-KEY-12345';

void mockHttp(
  HttpResult Function(String method, Uri uri, Map<String, String>? headers, String? body) make,
) {
  httpOverride = (String method, Uri uri, {Map<String, String>? headers, String? body}) async =>
      make(method, uri, headers, body);
}

HttpResult jsonRes(int status, Object body) => HttpResult(status, jsonEncode(body));

void main() {
  tearDown(() => httpOverride = null);

  group('OpenPhish المحلي', () {
    test('القاعدة غير محمّلة: skipped (مش آمن ولا خطر)', () {
      final r = OnlineIntel.feed('https://anything.example.org/');
      expect(r.status, IntelStatus.skipped);
      expect(r.findings, isEmpty);
    });

    test('تطابق كامل = تأكيد، تطابق مضيف = اشتباه قوي بدون تأكيد', () {
      ThreatFeed.instance.applyBody('https://evil-login.example.net/verify?id=1\n');
      final exact = OnlineIntel.feed('https://evil-login.example.net/verify?id=1');
      expect(exact.status, IntelStatus.hit);
      expect(exact.findings.single.confirmed, isTrue);
      final host = OnlineIntel.feed('https://evil-login.example.net/other');
      expect(host.status, IntelStatus.hit);
      expect(host.findings.single.confirmed, isFalse);
      expect(host.findings.single.points, 70);
      final clean = OnlineIntel.feed('https://unrelated.example.org/');
      expect(clean.status, IntelStatus.clean);
    });
  });

  group('Google Safe Browsing', () {
    test('بدون مفتاح: skipped ومفيش طلب شبكة', () async {
      mockHttp((m, u, h, b) => fail('لازم ما يتصلش بدون مفتاح'));
      final r = await OnlineIntel.safeBrowsing('https://a.example.com/', '');
      expect(r.status, IntelStatus.skipped);
    });

    test('تهديد: hit + confirmed + 80 نقطة، والطلب POST لنفس الخدمة', () async {
      late Uri seen;
      late String seenMethod;
      String? seenBody;
      mockHttp((m, u, h, b) {
        seen = u;
        seenMethod = m;
        seenBody = b;
        return jsonRes(200, <String, Object>{
          'matches': <Object>[
            <String, String>{'threatType': 'SOCIAL_ENGINEERING'},
          ],
        });
      });
      final r = await OnlineIntel.safeBrowsing('https://bad.example.com/x', _key);
      expect(r.status, IntelStatus.hit);
      expect(r.findings.single.confirmed, isTrue);
      expect(r.findings.single.points, 80);
      expect(seenMethod, 'POST');
      expect(seen.host, 'safebrowsing.googleapis.com');
      expect(seenBody, contains('https://bad.example.com/x'));
      expect(r.message.contains(_key), isFalse);
    });

    test('لا تطابق: clean لكن بدون نقاط، والنص يقول إنه لا يضمن الأمان', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{}));
      final r = await OnlineIntel.safeBrowsing('https://ok.example.com/', _key);
      expect(r.status, IntelStatus.clean);
      expect(r.findings.single.severity, Severity.good);
      expect(r.findings.single.points, 0);
      expect(r.findings.single.detail, contains('لا يعني أنه آمن'));
    });

    for (final code in <int>[400, 401, 403, 429, 500, 503]) {
      test('رد $code = error (فشل مصدر مش "نظيف")، والمفتاح مش في الرسالة', () async {
        mockHttp((m, u, h, b) => HttpResult(code, ''));
        final r = await OnlineIntel.safeBrowsing('https://a.example.com/', _key);
        expect(r.status, IntelStatus.error);
        expect(r.findings, isEmpty);
        expect(r.message.contains(_key), isFalse);
      });
    }

    test('رد JSON معطوب وأخطاء الشبكة = error', () async {
      mockHttp((m, u, h, b) => const HttpResult(200, '{not json'));
      expect((await OnlineIntel.safeBrowsing('https://a.example.com/', _key)).status,
          IntelStatus.error);
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw const SocketException('x');
      expect((await OnlineIntel.safeBrowsing('https://a.example.com/', _key)).status,
          IntelStatus.error);
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw TimeoutException('x');
      expect((await OnlineIntel.safeBrowsing('https://a.example.com/', _key)).status,
          IntelStatus.error);
    });
  });

  group('VirusTotal', () {
    Object stats({int mal = 0, int sus = 0, int harmless = 60, int undetected = 10}) =>
        <String, Object>{
          'data': <String, Object>{
            'attributes': <String, Object>{
              'last_analysis_stats': <String, int>{
                'malicious': mal,
                'suspicious': sus,
                'harmless': harmless,
                'undetected': undetected,
              },
            },
          },
        };

    test('بدون مفتاح: skipped', () async {
      mockHttp((m, u, h, b) => fail('لازم ما يتصلش بدون مفتاح'));
      expect((await OnlineIntel.virusTotal('https://a.example.com/', '')).status,
          IntelStatus.skipped);
    });

    test('المفتاح بيتبعت في الهيدر فقط مش في العنوان', () async {
      late Uri seen;
      Map<String, String>? seenHeaders;
      mockHttp((m, u, h, b) {
        seen = u;
        seenHeaders = h;
        return jsonRes(200, stats());
      });
      await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(seenHeaders?['x-apikey'], _key);
      expect(seen.toString().contains(_key), isFalse);
      expect(seen.host, 'www.virustotal.com');
    });

    test('3 محركات أو أكتر = تهديد مؤكد', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats(mal: 5)));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.status, IntelStatus.hit);
      expect(r.findings.single.confirmed, isTrue);
      expect(r.findings.single.points, 70);
    });

    test('محرك واحد = اشتباه بدون تأكيد', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats(mal: 1)));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.findings.single.confirmed, isFalse);
      expect(r.findings.single.points, 35);
    });

    test('مشبوه فقط = 20 نقطة', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats(sus: 2)));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.findings.single.points, 20);
    });

    test('لا رصد: clean بدون نقاط ومع تنبيه إنه لا يضمن الأمان', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats()));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.status, IntelStatus.clean);
      expect(r.findings.single.points, 0);
      expect(r.findings.single.detail, contains('لا يضمن'));
    });

    test('404 (لم يُفحص) = info مش clean، وبدون نتايج تحليل = info', () async {
      mockHttp((m, u, h, b) => const HttpResult(404, ''));
      expect((await OnlineIntel.virusTotal('https://a.example.com/', _key)).status,
          IntelStatus.info);
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{'data': <String, Object>{}}));
      expect((await OnlineIntel.virusTotal('https://a.example.com/', _key)).status,
          IntelStatus.info);
    });

    for (final code in <int>[401, 403, 429, 500]) {
      test('رد $code = error', () async {
        mockHttp((m, u, h, b) => HttpResult(code, ''));
        final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
        expect(r.status, IntelStatus.error);
        expect(r.message.contains(_key), isFalse);
      });
    }
  });

  group('عمر الدومين (RDAP)', () {
    HttpResult registeredDaysAgo(int days) {
      final d = DateTime.now().toUtc().subtract(Duration(days: days));
      return jsonRes(200, <String, Object>{
        'events': <Object>[
          <String, String>{
            'eventAction': 'registration',
            'eventDate': d.toIso8601String(),
          },
        ],
      });
    }

    test('دومين عمره 3 أيام: خطر 40 نقطة', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(3));
      final r = await OnlineIntel.rdap('new.example.com');
      expect(r.status, IntelStatus.hit);
      expect(r.findings.single.points, 40);
      expect(r.findings.single.confirmed, isFalse);
    });

    test('دومين عمره 15 يوم = 30، و60 يوم = 15، و200 يوم = 5', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(15));
      expect((await OnlineIntel.rdap('a.example.com')).findings.single.points, 30);
      mockHttp((m, u, h, b) => registeredDaysAgo(60));
      expect((await OnlineIntel.rdap('a.example.com')).findings.single.points, 15);
      mockHttp((m, u, h, b) => registeredDaysAgo(200));
      expect((await OnlineIntel.rdap('a.example.com')).findings.single.points, 5);
    });

    test('دومين قديم: clean بدون نقاط', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(2000));
      final r = await OnlineIntel.rdap('old.example.com');
      expect(r.status, IntelStatus.clean);
      expect(r.findings.single.points, 0);
    });

    test('404 / بدون تاريخ = skipped، و500 = error', () async {
      mockHttp((m, u, h, b) => const HttpResult(404, ''));
      expect((await OnlineIntel.rdap('a.example.com')).status, IntelStatus.skipped);
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{'events': <Object>[]}));
      expect((await OnlineIntel.rdap('a.example.com')).status, IntelStatus.skipped);
      mockHttp((m, u, h, b) => const HttpResult(500, ''));
      expect((await OnlineIntel.rdap('a.example.com')).status, IntelStatus.error);
    });
  });
}
