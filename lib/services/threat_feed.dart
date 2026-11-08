import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'http_util.dart';
import 'url_analyzer.dart';

class FeedMatch {
  const FeedMatch(this.kind, this.points);

  final String kind; // exact | host | domain
  final int points;
}

/// نتيجة قراءة نص الخلاصة (قبل ما تتعتمد).
class FeedParse {
  FeedParse._(this.urls, this.hosts, this.domains, this.validLines, this.rejectedLines);

  final Set<String> urls;
  final Set<String> hosts;
  final Set<String> domains;

  /// عدد الأسطر الصالحة / المرفوضة (التعليقات والأسطر الفاضية مش محسوبة).
  final int validLines;
  final int rejectedLines;

  /// الأسطر الصالحة بعد التطبيع، بتتحفظ في الملف بدل الرد الخام.
  List<String> keptLines = <String>[];
}

/// قاعدة روابط التصيّد (OpenPhish Community Feed) محفوظة محليًا.
/// بعد التحديث يتم الفحص بدون إنترنت ولا يُرسل أي رابط لأي جهة.
/// تنبيه: الخلاصة للاستخدام غير التجاري فقط حسب شروط OpenPhish.
///
/// التحديث آمن وذري: بنقرأ الرد في مجموعات مؤقتة ونتحقق منه (مش مقطوع، أغلبه
/// أسطر روابط صالحة، مش أصغر بكتير من القاعدة الحالية) وبس بعدين نبدّل القاعدة
/// ونكتب الملف عبر ملف مؤقت + rename. لو أي شرط فشل القاعدة القديمة بتفضل زي ما هي.
class ThreatFeed extends ChangeNotifier {
  ThreatFeed._() : _dirProvider = null;

  @visibleForTesting
  ThreatFeed.forTest({required Future<Directory> Function() dirProvider})
      : _dirProvider = dirProvider;

  final Future<Directory> Function()? _dirProvider;

  static const String _fileName = 'cobra_openphish.txt';

  static final ThreatFeed instance = ThreatFeed._();

  static const String feedUrl =
      'https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt';

  static const int maxEntries = 100000;
  static const int maxLineLength = 2048;

  /// أقل نسبة أسطر صالحة (من غير التعليقات) عشان نقبل الرد.
  static const double minValidRatio = 0.8;

  /// لو القاعدة الحالية كبيرة، الجديدة لازم تكون على الأقل بالنسبة دي منها.
  static const double minSizeVsPrevious = 0.2;
  static const int previousSizeThreshold = 100;

  Set<String> _urls = <String>{};
  Set<String> _hosts = <String>{};
  Set<String> _domains = <String>{};
  DateTime? _updated;
  bool _busy = false;
  String? lastError;

  int get count => _urls.length;
  DateTime? get updated => _updated;
  bool get busy => _busy;

  /// مجلد التخزين: مجلد بيانات التطبيق الدائم (مش بيتمسح من النظام زي المجلد المؤقت).
  Future<Directory> _storageDir() async {
    final custom = _dirProvider;
    if (custom != null) return custom();
    try {
      return await getApplicationSupportDirectory();
    } catch (_) {
      return Directory.systemTemp;
    }
  }

  Future<void> load() async {
    try {
      final dir = await _storageDir();
      var f = File('${dir.path}/$_fileName');
      if (!await f.exists() && _dirProvider == null) {
        // ترحيل: النسخة القديمة كانت في المجلد المؤقت
        final old = File('${Directory.systemTemp.path}/$_fileName');
        if (await old.exists()) f = old;
      }
      if (!await f.exists()) return;
      final p = parse(await f.readAsString());
      // ملف تالف أو فاضي: نتجاهله وسيُعاد التحميل عند التحديث
      if (p.urls.isEmpty) return;
      _swap(p);
      _updated = await f.lastModified();
      notifyListeners();
    } catch (_) {
      // ملف تالف: نتجاهله وسيُعاد التحميل عند التحديث
    }
  }

  static String normalize(String url) {
    var s = url.trim().toLowerCase();
    s = s.replaceFirst(RegExp(r'^[a-z][a-z0-9+.\-]*://'), '');
    final hash = s.indexOf('#');
    if (hash >= 0) s = s.substring(0, hash);
    while (s.endsWith('/')) {
      s = s.substring(0, s.length - 1);
    }
    return s;
  }

  static String _hostOf(String normalized) {
    final end = normalized.indexOf(RegExp(r'[/?]'));
    var host = end >= 0 ? normalized.substring(0, end) : normalized;
    final at = host.lastIndexOf('@');
    if (at >= 0) host = host.substring(at + 1);
    final colon = host.indexOf(':');
    if (colon >= 0) host = host.substring(0, colon);
    return host;
  }

  static final RegExp _httpLine = RegExp(r'^https?://', caseSensitive: false);

  /// يقرأ نص الخلاصة في مجموعات جديدة (من غير ما يلمس القاعدة الحالية).
  @visibleForTesting
  static FeedParse parse(String text) {
    final urls = <String>{};
    final hosts = <String>{};
    final domains = <String>{};
    final kept = <String>[];
    var valid = 0;
    var rejected = 0;
    for (final line in text.split('\n')) {
      final l = line.trim();
      if (l.isEmpty || l.startsWith('#')) continue;
      if (!_httpLine.hasMatch(l) ||
          l.length > maxLineLength ||
          l.contains(RegExp(r'\s'))) {
        rejected++;
        continue;
      }
      final u = normalize(l);
      final host = _hostOf(u);
      if (u.isEmpty || host.isEmpty) {
        rejected++;
        continue;
      }
      valid++;
      if (urls.add(u)) {
        hosts.add(host);
        domains.add(UrlAnalyzer.registrableDomain(host));
        kept.add(l);
      }
      if (urls.length >= maxEntries) break;
    }
    return FeedParse._(urls, hosts, domains, valid, rejected)..keptLines = kept;
  }

  /// null لو الخلاصة مقبولة، وإلا سبب الرفض.
  @visibleForTesting
  static String? validate(FeedParse p, {required int previousCount}) {
    if (p.urls.isEmpty) return 'الملف فارغ أو بصيغة غير معروفة';
    final total = p.validLines + p.rejectedLines;
    if (total > 0 && p.validLines / total < minValidRatio) {
      return 'الملف مش بصيغة الخلاصة المتوقعة';
    }
    if (previousCount >= previousSizeThreshold &&
        p.urls.length < previousCount * minSizeVsPrevious) {
      return 'الخلاصة الجديدة أصغر بكتير من الحالية، اتجاهلت للحماية';
    }
    return null;
  }

  void _swap(FeedParse p) {
    _urls = p.urls;
    _hosts = p.hosts;
    _domains = p.domains;
  }

  /// يعتمد نص خلاصة في الذاكرة (قراءة + تحقق + تبديل). يرجّع سبب الرفض أو null.
  /// لا يكتب ملفات؛ الكتابة في [update].
  @visibleForTesting
  String? applyBody(String body) {
    final p = parse(body);
    final why = validate(p, previousCount: _urls.length);
    if (why != null) return why;
    _swap(p);
    return null;
  }

  Future<void> _persist(FeedParse p) async {
    try {
      final dir = await _storageDir();
      if (!await dir.exists()) await dir.create(recursive: true);
      final tmp = File('${dir.path}/$_fileName.tmp');
      await tmp.writeAsString('${p.keptLines.join('\n')}\n', flush: true);
      await tmp.rename('${dir.path}/$_fileName');
    } catch (_) {
      // لو تعذر الحفظ نكمل بالنسخة التي في الذاكرة
    }
  }

  Future<bool> update() async {
    if (_busy) return false;
    _busy = true;
    lastError = null;
    notifyListeners();
    try {
      final r = await httpRequest(
        'GET',
        Uri.parse(feedUrl),
        timeout: const Duration(seconds: 30),
        maxBytes: 12 * 1024 * 1024,
      );
      if (r.status != 200) {
        lastError = 'رد غير متوقع من السيرفر (${r.status})';
        return false;
      }
      if (r.truncated) {
        // رد مقطوع: آخر سطر ممكن يكون ناقص والقائمة غير كاملة
        lastError = 'الملف أكبر من الحد المسموح، اتجاهل التحديث';
        return false;
      }
      final p = parse(r.body);
      final why = validate(p, previousCount: _urls.length);
      if (why != null) {
        lastError = why;
        return false;
      }
      _swap(p);
      await _persist(p);
      _updated = DateTime.now();
      return true;
    } on TimeoutException {
      lastError = 'انتهت المهلة';
      return false;
    } on SocketException {
      lastError = 'لا يوجد اتصال بالإنترنت';
      return false;
    } catch (_) {
      lastError = 'تعذر التحديث';
      return false;
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  /// يفحص رابطًا: تطابق كامل ← مضيف ← دومين أساسي.
  FeedMatch? match(String url) {
    if (_urls.isEmpty) return null;
    final n = normalize(url);
    if (_urls.contains(n)) return const FeedMatch('exact', 90);
    final host = _hostOf(n);
    if (host.isEmpty || UrlAnalyzer.isSharedHost(host)) return null;
    if (_hosts.contains(host)) return const FeedMatch('host', 70);
    final d = UrlAnalyzer.registrableDomain(host);
    if (_domains.contains(d)) return const FeedMatch('domain', 45);
    return null;
  }
}
