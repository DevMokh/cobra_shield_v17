import 'dart:async';
import 'dart:io';

import 'net_guard.dart';

class ExpandResult {
  const ExpandResult({
    required this.chain,
    this.statusCode,
    this.error,
    this.blockedHop,
  });

  final List<String> chain; // الرابط الأصلي ثم كل تحويلة
  final int? statusCode;
  final String? error;

  /// رقم الحلقة اللي اتمنع الاتصال بيها (0 = الرابط الأصلي نفسه). null لو مفيش منع.
  final int? blockedHop;

  String get finalUrl => chain.last;
  bool get redirected => chain.length > 1;

  /// الحارس منع الاتصال بوجهة (محلية/داخلية/غير ويب...)، ومحصلش اتصال بيها.
  bool get blocked => blockedHop != null;

  /// المنع حصل على وجهة تحويلة (يعني رابط خارجي بيحوّل لوجهة داخلية): علامة خطر.
  bool get blockedOnRedirect => blockedHop != null && blockedHop! > 0;
}

class _Probe {
  const _Probe(this.status, this.location);
  final int status;
  final String? location;
}

/// يتتبع تحويلات الرابط (HEAD فقط، بدون تحميل أي محتوى) ليكشف الوجهة الحقيقية.
/// تنبيه: ده بيتصل فعليًا بالسيرفر، فالتطبيق يطلب موافقة المستخدم قبله.
///
/// حماية الشبكة (راجع NetGuard):
///  1) كل رابط (الأصلي وكل تحويلة) بيتفحص شكله قبل الاتصال.
///  2) وقت الاتصال نفسه بنعمل DNS lookup بأنفسنا، ونتحقق من *كل* العناوين، ونتصل
///     بالعنوان اللي اتحقق منه بالتحديد (connectionFactory). فمفيش فجوة بين
///     "اتحققنا" و"اتصلنا"، وده بيقفل هجوم DNS rebinding في الاتصالات الجديدة.
///     (اتصال keep-alive معاد استخدامه بيكون لنفس العنوان اللي اتحقق منه أصلًا.)
///  3) مفيش بروكسي، ومفيش قبول لشهادات غير صالحة.
class LinkExpander {
  LinkExpander._();

  static const int maxHops = 8;
  static const int maxLocationLength = 2048;
  static const Duration _timeout = Duration(seconds: 8);
  static const Duration _totalBudget = Duration(seconds: 30);

  static Future<_Probe> _probe(HttpClient client, Uri uri, String method) async {
    final req = await client.openUrl(method, uri).timeout(_timeout);
    req.followRedirects = false;
    req.headers.set(HttpHeaders.acceptHeader, '*/*');
    final res = await req.close().timeout(_timeout);
    final loc = res.headers.value(HttpHeaders.locationHeader);
    final status = res.statusCode;
    // لا نحمّل أي محتوى: نقطع الاتصال فورًا
    final sub = res.listen((_) {});
    await sub.cancel();
    return _Probe(status, loc);
  }

  static Future<ExpandResult> expand(String url) async {
    final chain = <String>[url];
    String? blockedReason; // بيتملي لو الحارس منع اتصال (من أي مكان)
    int? status;

    final client = HttpClient()
      ..connectionTimeout = _timeout
      ..userAgent = 'Mozilla/5.0 (Linux; Android 14) CobraShield/1.0'
      ..findProxy = (Uri _) => 'DIRECT';

    // الاتصال بالعنوان اللي اتحقق منه بالتحديد (ضد DNS rebinding).
    // مهم: لما بنستخدم connectionFactory الـ HttpClient مبيعملش TLS لوحده،
    // فلازم نرجّع SecureSocket بنفسنا لروابط https. اسم الدومين بيفضل محفوظ
    // جوه InternetAddress (طالع من lookup) فالتحقق من الشهادة بيتم على الاسم.
    client.connectionFactory =
        (Uri target, String? proxyHost, int? proxyPort) async {
      if (proxyHost != null) {
        const msg = 'الاتصال عبر بروكسي غير مسموح في الفحص.';
        blockedReason = msg;
        throw const BlockedTargetException(msg);
      }
      final addrs = await InternetAddress.lookup(target.host).timeout(_timeout);
      final InternetAddress ip;
      try {
        ip = NetGuard.pickSafeAddress(addrs);
      } on BlockedTargetException catch (e) {
        blockedReason = e.reason;
        rethrow;
      }
      if (target.isScheme('https')) {
        return SecureSocket.startConnect(ip, target.port);
      }
      return Socket.startConnect(ip, target.port);
    };

    ExpandResult fail(String message, {int? blockedHop}) => ExpandResult(
          chain: chain,
          statusCode: status,
          error: message,
          blockedHop: blockedHop,
        );

    final clock = Stopwatch()..start();
    try {
      var current = Uri.parse(url);
      for (var hop = 0; hop < maxHops; hop++) {
        if (clock.elapsed > _totalBudget) {
          return fail('انتهت المهلة الكلية لتتبع التحويلات.');
        }
        final reason = NetGuard.blockReason(current);
        if (reason != null) {
          return fail(
            hop == 0
                ? 'لم نتصل بالرابط: $reason'
                : 'تحويلة رقم $hop تشير لوجهة غير آمنة، فتوقفنا ولم نتصل بها: $reason',
            blockedHop: hop,
          );
        }
        var p = await _probe(client, current, 'HEAD');
        if (p.status == 405 ||
            p.status == 501 ||
            p.status == 400 ||
            p.status == 403) {
          // بعض السيرفرات ترفض HEAD
          p = await _probe(client, current, 'GET');
        }
        status = p.status;
        final loc = p.location;
        if (p.status >= 300 && p.status < 400 && loc != null && loc.isNotEmpty) {
          if (loc.length > maxLocationLength) {
            return fail('عنوان التحويلة طويل بشكل غير طبيعي وهذا مريب.');
          }
          final next = current.resolve(loc);
          if (chain.contains(next.toString())) {
            return fail('التحويلات بتدور في حلقة مفرغة وهذا مريب.');
          }
          current = next;
          chain.add(current.toString());
          continue;
        }
        return ExpandResult(chain: chain, statusCode: status);
      }
      return fail('عدد التحويلات كبير (أكثر من $maxHops) وهذا مريب.');
    } on BlockedTargetException catch (e) {
      return fail(
        'تم إيقاف الاتصال: ${e.reason}',
        blockedHop: chain.length - 1,
      );
    } on TimeoutException {
      if (blockedReason != null) {
        return fail('تم إيقاف الاتصال: $blockedReason', blockedHop: chain.length - 1);
      }
      return fail('انتهت المهلة: السيرفر لم يرد.');
    } on HandshakeException {
      return fail('شهادة الأمان (SSL) غير صالحة لهذا الموقع.');
    } on SocketException {
      return fail('تعذر الاتصال: الموقع غير موجود أو لا يوجد إنترنت.');
    } on FormatException {
      return fail('تحويلة بعنوان غير صالح وهذا مريب.');
    } catch (_) {
      // لو الحارس هو سبب الخطأ (حتى لو اتغلّف الاستثناء) نقول كده بدل رسالة عامة
      final why = blockedReason;
      if (why != null) {
        return fail('تم إيقاف الاتصال: $why', blockedHop: chain.length - 1);
      }
      return fail('تعذر فحص الرابط (رد غير متوقع).');
    } finally {
      client.close(force: true);
    }
  }
}
