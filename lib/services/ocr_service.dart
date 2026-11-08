import 'dart:async';

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:flutter/services.dart';
import 'package:google_mlkit_text_recognition/google_mlkit_text_recognition.dart';

import 'ocr_text.dart';

/// المحرك اللي اتستخدم فعليًا في آخر قراءة.
enum OcrEngine {
  /// Tesseract على الجهاز: عربي + إنجليزي.
  tesseract,

  /// ML Kit (لاتيني فقط): إنجليزي وأرقام وروابط، ومبيقراش العربي.
  mlkitLatin,
}

/// نتيجة قراءة صورة، مع المحرك المستخدم عشان الواجهة تقول للمستخدم الحقيقة.
class OcrOutcome {
  const OcrOutcome({
    required this.text,
    required this.engine,
    this.fallbackReason,
  });

  final String text;
  final OcrEngine engine;

  /// سبب الرجوع للمحرك اللاتيني (null لو Tesseract اشتغل عادي).
  final String? fallbackReason;

  bool get readsArabic => engine == OcrEngine.tesseract;
}

/// استخراج نص من صورة (سكرين شوت رسالة) على الجهاز بالكامل، بدون إنترنت.
///
/// الأساسي: Tesseract (عربي + إنجليزي) عن طريق كود أندرويد أصلي (قناة cobra/ocr).
/// لو المحرك الأساسي مش متاح أو فشل (نموذج ناقص، ذاكرة، مهلة...) بنرجع تلقائيًا
/// لـ ML Kit اللاتيني، وبنرجّع في النتيجة إن العربي ما اتقراش، فالواجهة تنبّه
/// المستخدم. لو المحركين فشلوا بيترمي استثناء (الفشل مش معناه "الصورة آمنة").
class OcrService {
  OcrService._();

  static const MethodChannel _channel = MethodChannel('cobra/ocr');
  static const Duration _tesseractTimeout = Duration(seconds: 60);

  static TextRecognizer? _recognizer;

  /// للاختبارات فقط: بديل للمحرك اللاتيني (ML Kit).
  @visibleForTesting
  static Future<String> Function(String path)? latinFallbackOverride;

  static TextRecognizer get _latin =>
      _recognizer ??= TextRecognizer(script: TextRecognitionScript.latin);

  static Future<OcrOutcome> extract(String path) async {
    String reason;
    try {
      final String? raw = await _channel
          .invokeMethod<String>('recognize', <String, String>{'path': path})
          .timeout(_tesseractTimeout);
      return OcrOutcome(
        text: cleanOcrText(raw ?? ''),
        engine: OcrEngine.tesseract,
      );
    } on MissingPluginException {
      reason = 'unavailable';
    } on PlatformException catch (e) {
      reason = e.code;
    } on TimeoutException {
      reason = 'timeout';
    }

    final override = latinFallbackOverride;
    final String latinText = override != null
        ? await override(path)
        : (await _latin.processImage(InputImage.fromFilePath(path))).text;
    return OcrOutcome(
      text: cleanOcrText(latinText),
      engine: OcrEngine.mlkitLatin,
      fallbackReason: reason,
    );
  }

  static Future<void> dispose() async {
    await _recognizer?.close();
    _recognizer = null;
  }
}
