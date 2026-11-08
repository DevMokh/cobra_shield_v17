import 'package:cobra_shield/services/ocr_service.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const MethodChannel _channel = MethodChannel('cobra/ocr');

void mockChannel(Future<Object?>? Function(MethodCall call)? handler) {
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(_channel, handler);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  tearDown(() {
    mockChannel(null);
    OcrService.latinFallbackOverride = null;
  });

  test('Tesseract شغّال: النص بيتنضّف والمحرك يقرأ العربي', () async {
    String? seenPath;
    mockChannel((call) async {
      expect(call.method, 'recognize');
      seenPath = (call.arguments as Map<Object?, Object?>)['path'] as String?;
      return 'مرحبا\f\r\nhttp://a.example.com  \n\n\n\nشكرا';
    });
    OcrService.latinFallbackOverride = (_) async => fail('لازم ما يرجعش للاحتياطي');
    final o = await OcrService.extract('/tmp/shot.png');
    expect(seenPath, '/tmp/shot.png');
    expect(o.engine, OcrEngine.tesseract);
    expect(o.readsArabic, isTrue);
    expect(o.fallbackReason, isNull);
    expect(o.text, 'مرحبا\nhttp://a.example.com\n\nشكرا');
  });

  test('صورة بدون نص: نص فاضي من Tesseract (بدون رجوع للاحتياطي)', () async {
    mockChannel((call) async => '');
    OcrService.latinFallbackOverride = (_) async => fail('لازم ما يرجعش للاحتياطي');
    final o = await OcrService.extract('/tmp/blank.png');
    expect(o.engine, OcrEngine.tesseract);
    expect(o.text, '');
  });

  test('فشل Tesseract (PlatformException): رجوع لـ ML Kit واللغة العربية غير مدعومة', () async {
    mockChannel((call) async => throw PlatformException(code: 'ocr_failed', message: 'x'));
    OcrService.latinFallbackOverride = (path) async => 'hello  \f';
    final o = await OcrService.extract('/tmp/shot.png');
    expect(o.engine, OcrEngine.mlkitLatin);
    expect(o.readsArabic, isFalse);
    expect(o.fallbackReason, 'ocr_failed');
    expect(o.text, 'hello');
  });

  test('القناة غير موجودة (MissingPluginException): سبب unavailable', () async {
    mockChannel(null);
    OcrService.latinFallbackOverride = (_) async => 'english text';
    final o = await OcrService.extract('/tmp/shot.png');
    expect(o.engine, OcrEngine.mlkitLatin);
    expect(o.fallbackReason, 'unavailable');
    expect(o.text, 'english text');
  });

  test('لو المحركين فشلوا يترمي استثناء (الفشل مش "آمن")', () async {
    mockChannel((call) async => throw PlatformException(code: 'ocr_failed'));
    OcrService.latinFallbackOverride = (_) async => throw StateError('mlkit failed');
    expect(() => OcrService.extract('/tmp/shot.png'), throwsA(isA<StateError>()));
  });
}
