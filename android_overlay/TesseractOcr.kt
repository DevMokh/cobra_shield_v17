package com.cobrashield.cobra_shield

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import com.googlecode.tesseract.android.TessBaseAPI
import java.io.File
import java.io.FileOutputStream
import kotlin.math.max

/**
 * قراءة نص عربي + إنجليزي من صورة على الجهاز بالكامل (Tesseract).
 * نماذج اللغة (tessdata_fast) بتتنسخ مرة واحدة من assets لمجلد التطبيق الخاص.
 * مفيش أي اتصال بالإنترنت وقت القراءة.
 */
object TesseractOcr {
    private const val LANGS = "ara+eng"
    private val DATA_FILES = arrayOf("ara.traineddata", "eng.traineddata")

    /** أقصى طول لأي ضلع بعد التصغير (يحمي الذاكرة من الصور الكبيرة جدًا) */
    private const val MAX_SIDE = 2600

    private fun ensureData(context: Context): String {
        val root = File(context.filesDir, "tesseract")
        val dir = File(root, "tessdata")
        if (!dir.exists() && !dir.mkdirs()) {
            throw IllegalStateException("cannot create tessdata dir")
        }
        for (name in DATA_FILES) {
            val out = File(dir, name)
            if (out.exists() && out.length() > 0L) continue
            // نكتب في ملف مؤقت ثم نعمل rename: عشان ما يتبقاش ملف نصف مكتوب
            val tmp = File(dir, "$name.part")
            context.assets.open("tessdata/$name").use { input ->
                FileOutputStream(tmp).use { output -> input.copyTo(output) }
            }
            if (!tmp.renameTo(out)) {
                tmp.delete()
                throw IllegalStateException("cannot install $name")
            }
        }
        return root.absolutePath
    }

    private fun loadBitmap(path: String): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(path, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

        var sample = 1
        val longest = max(bounds.outWidth, bounds.outHeight)
        while (longest / sample > MAX_SIDE) sample *= 2

        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        var bmp = BitmapFactory.decodeFile(path, opts) ?: return null

        // تصحيح اتجاه صور الكاميرا (EXIF)
        val degrees = try {
            when (
                ExifInterface(path).getAttributeInt(
                    ExifInterface.TAG_ORIENTATION,
                    ExifInterface.ORIENTATION_NORMAL
                )
            ) {
                ExifInterface.ORIENTATION_ROTATE_90 -> 90f
                ExifInterface.ORIENTATION_ROTATE_180 -> 180f
                ExifInterface.ORIENTATION_ROTATE_270 -> 270f
                else -> 0f
            }
        } catch (e: Exception) {
            0f
        }
        if (degrees != 0f) {
            val m = Matrix()
            m.postRotate(degrees)
            val rotated = Bitmap.createBitmap(bmp, 0, 0, bmp.width, bmp.height, m, true)
            if (rotated !== bmp) bmp.recycle()
            bmp = rotated
        }
        return bmp
    }

    /** يرجّع النص المقروء (ممكن يكون فاضي لو مفيش نص). يرمي استثناء لو فشل المحرك. */
    fun recognize(context: Context, path: String): String {
        val bitmap = loadBitmap(path) ?: throw IllegalArgumentException("cannot decode image")
        val api = TessBaseAPI()
        try {
            val dataPath = ensureData(context)
            if (!api.init(dataPath, LANGS)) {
                throw IllegalStateException("tesseract init failed")
            }
            api.setPageSegMode(TessBaseAPI.PageSegMode.PSM_AUTO)
            api.setImage(bitmap)
            return api.getUTF8Text() ?: ""
        } finally {
            api.recycle()
            bitmap.recycle()
        }
    }
}
