import 'dart:async';
import 'dart:io';

import 'package:cobra_shield/services/http_util.dart';
import 'package:cobra_shield/services/threat_feed.dart';
import 'package:flutter_test/flutter_test.dart';

const String _good = '''
https://evil-login.example.net/verify?id=1
http://bad.test-site.xyz/a/b/
https://another.phish.top/path
''';

void main() {
  late Directory dir;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('cobra_feed_test');
  });

  tearDown(() async {
    httpOverride = null;
    if (await dir.exists()) await dir.delete(recursive: true);
  });

  ThreatFeed newFeed() => ThreatFeed.forTest(dirProvider: () async => dir);
  File feedFile() => File('${dir.path}/cobra_openphish.txt');

  void respond(HttpResult Function() make) {
    httpOverride = (String method, Uri uri, {Map<String, String>? headers, String? body}) async {
      expect(method, 'GET');
      expect(uri.scheme, 'https');
      return make();
    };
  }

  test('تحديث ناجح: يحمّل ويحفظ الملف ومفيش ملف مؤقت متبقي', () async {
    final f = newFeed();
    respond(() => const HttpResult(200, _good));
    expect(await f.update(), isTrue);
    expect(f.count, 3);
    expect(f.lastError, isNull);
    expect(f.updated, isNotNull);
    expect(f.busy, isFalse);
    expect(await feedFile().exists(), isTrue);
    expect(await File('${dir.path}/cobra_openphish.txt.tmp').exists(), isFalse);
    expect((await feedFile().readAsString()).trim().split('\n').length, 3);
  });

  test('instance جديدة تقرأ الملف المحفوظ', () async {
    respond(() => const HttpResult(200, _good));
    expect(await newFeed().update(), isTrue);
    final again = newFeed();
    expect(again.count, 0);
    await again.load();
    expect(again.count, 3);
    expect(again.match('https://evil-login.example.net/verify?id=1')?.kind, 'exact');
  });

  test('رد غير 200: القاعدة والملف القديمين بيفضلوا زي ما هما', () async {
    final f = newFeed();
    respond(() => const HttpResult(200, _good));
    expect(await f.update(), isTrue);
    final before = await feedFile().readAsString();

    respond(() => const HttpResult(503, ''));
    expect(await f.update(), isFalse);
    expect(f.lastError, contains('503'));
    expect(f.count, 3);
    expect(await feedFile().readAsString(), before);
  });

  test('رد مقطوع (truncated) يترفض ومبيلمسش القاعدة', () async {
    final f = newFeed();
    respond(() => const HttpResult(200, _good));
    expect(await f.update(), isTrue);
    final before = await feedFile().readAsString();

    respond(() => const HttpResult(200, 'https://a.example.org/x\n', truncated: true));
    expect(await f.update(), isFalse);
    expect(f.lastError, isNotNull);
    expect(f.count, 3);
    expect(await feedFile().readAsString(), before);
  });

  test('رد معطوب (HTML) يترفض ومبيمسحش القاعدة', () async {
    final f = newFeed();
    respond(() => const HttpResult(200, _good));
    expect(await f.update(), isTrue);
    final before = await feedFile().readAsString();

    respond(() => const HttpResult(200, '<html><body>Error</body></html>'));
    expect(await f.update(), isFalse);
    expect(f.count, 3);
    expect(await feedFile().readAsString(), before);
  });

  test('أخطاء الشبكة بتتحول لرسالة ومبتكسرش القاعدة', () async {
    final f = newFeed();
    respond(() => const HttpResult(200, _good));
    expect(await f.update(), isTrue);

    httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
        throw const SocketException('no route');
    expect(await f.update(), isFalse);
    expect(f.lastError, 'لا يوجد اتصال بالإنترنت');

    httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
        throw TimeoutException('slow');
    expect(await f.update(), isFalse);
    expect(f.lastError, 'انتهت المهلة');
    expect(f.count, 3);
  });

  test('ملف محفوظ تالف يتجاهل عند التحميل', () async {
    await feedFile().writeAsString('<<<garbage>>>\nnot urls\n');
    final f = newFeed();
    await f.load();
    expect(f.count, 0);
  });

  test('httpRequest يرفض أي رابط غير https', () async {
    expect(
      () => httpRequest('GET', Uri.parse('http://example.com/feed.txt')),
      throwsA(isA<ArgumentError>()),
    );
  });
}
