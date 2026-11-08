import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart' show visibleForTesting;

class HttpResult {
  const HttpResult(this.status, this.body, {this.truncated = false});

  final int status;
  final String body;

  /// الرد تجاوز الحد الأقصى للحجم وتم قطعه (فالمحتوى ناقص).
  final bool truncated;
}

/// بديل للشبكة في الاختبارات فقط: لو اتحدد، [httpRequest] بيستدعيه بدل ما يتصل بالإنترنت.
/// (بعد التحقق من https عشان الاختبارات تغطي القاعدة دي كمان).
typedef HttpOverride = Future<HttpResult> Function(
  String method,
  Uri uri, {
  Map<String, String>? headers,
  String? body,
});

@visibleForTesting
HttpOverride? httpOverride;

/// طلب HTTP بسيط بمهلة وحد أقصى لحجم الرد (بدون أي حزمة خارجية).
///
/// للاستخدام مع خدمات ثابتة معروفة فقط (OpenPhish, RDAP, Google, VirusTotal):
/// بيرفض أي رابط غير https. لو الرد أكبر من [maxBytes] بيتقطع وبيرجّع
/// `truncated: true` عشان اللي بيستدعي ميتعاملش مع محتوى ناقص كأنه كامل.
Future<HttpResult> httpRequest(
  String method,
  Uri uri, {
  Map<String, String>? headers,
  String? body,
  Duration timeout = const Duration(seconds: 10),
  int maxBytes = 2 * 1024 * 1024,
  bool follow = true,
}) async {
  if (!uri.isScheme('https')) {
    throw ArgumentError('https only');
  }
  final override = httpOverride;
  if (override != null) {
    return override(method, uri, headers: headers, body: body);
  }
  final client = HttpClient()
    ..connectionTimeout = timeout
    ..userAgent = 'CobraShield/1.2';
  try {
    final req = await client.openUrl(method, uri).timeout(timeout);
    req.followRedirects = follow;
    req.maxRedirects = 5;
    if (headers != null) {
      for (final e in headers.entries) {
        req.headers.set(e.key, e.value);
      }
    }
    if (body != null) {
      final bytes = utf8.encode(body);
      req.headers.contentLength = bytes.length;
      req.add(bytes);
    }
    final res = await req.close().timeout(timeout);
    final chunks = <int>[];
    var truncated = false;
    await for (final c in res.timeout(timeout)) {
      chunks.addAll(c);
      if (chunks.length > maxBytes) {
        truncated = true;
        break;
      }
    }
    return HttpResult(
      res.statusCode,
      utf8.decode(chunks, allowMalformed: true),
      truncated: truncated,
    );
  } finally {
    client.close(force: true);
  }
}
