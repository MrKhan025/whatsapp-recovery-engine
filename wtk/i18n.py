"""Multi-language internationalization (`wtk/i18n.py`) for English, Hindi, and Urdu (v2.0)."""

from __future__ import annotations

from typing import Any

TEXT: dict[str, dict[str, str]] = {
    "en": {
        "dir": "ltr",
        "title": "WhatsApp Recovery Engine v2.0",
        "subtitle": "Professional Digital Forensics, Backup Intelligence, Media Discovery & Dual SHA-256/512 Verification",
        "scan": "Scan Folder",
        "load_sample": "Load Sample Data",
        "privacy": "Files stay on this device. 100% read-only local processing.",
        "kpi_files": "Files Scanned",
        "kpi_media": "Accessible Media",
        "kpi_backups": "Backup Candidates",
        "kpi_dupes": "Duplicate Groups",
        "readiness_title": "Recovery Readiness Assessment",
        "disclaimer": (
            "Only scan files you own or are authorized to inspect. Encrypted .crypt* backups are never brute-forced. "
            "Deleted messages cannot be recovered unless present in an accessible source."
        ),
    },
    "hi": {
        "dir": "ltr",
        "title": "व्हाट्सऐप रिकवरी इंजन v2.0",
        "subtitle": "डिजिटल फोरेंसिक, बैकअप विश्लेषण, मीडिया खोज और SHA-256/512 सत्यापन मंच",
        "scan": "फ़ोल्डर स्कैन करें",
        "load_sample": "नमूना डेटा लोड करें",
        "privacy": "फ़ाइलें इसी डिवाइस पर रहती हैं। 100% रीड-ओनली लोकल प्रोसेसिंग।",
        "kpi_files": "स्कैन की गई फ़ाइलें",
        "kpi_media": "उपलब्ध मीडिया",
        "kpi_backups": "बैकअप फ़ाइलें",
        "kpi_dupes": "डुप्लिकेट समूह",
        "readiness_title": "रिकवरी तत्परता मूल्यांकन",
        "disclaimer": (
            "केवल उन्हीं फ़ाइलों को स्कैन करें जिनके आप स्वामी हैं। एन्क्रिप्टेड .crypt* बैकअप बिना अधिकृत कुंजी के डिक्रिप्ट नहीं किए जाते हैं।"
        ),
    },
    "ur": {
        "dir": "rtl",
        "title": "واٹس ایپ ریکوری انجن v2.0",
        "subtitle": "ڈیجیٹل فرانزک، بیک اپ تجزیہ، میڈیا دریافت اور SHA-256/512 تصدیقی پلیٹ فارم",
        "scan": "فولڈر اسکین کریں",
        "load_sample": "نمونہ ڈیٹا لوڈ کریں",
        "privacy": "فائلیں اسی ڈیوائس پر رہتی ہیں۔ مکمل طور پر لوکل اور محفوظ پروسیسنگ۔",
        "kpi_files": "اسکین شدہ فائلیں",
        "kpi_media": "دستیاب میڈیا",
        "kpi_backups": "بیک اپ فائلیں",
        "kpi_dupes": "ڈپلیکیٹ گروپس",
        "readiness_title": "ریکوری تیاری کا جائزہ",
        "disclaimer": (
            "صرف ان فائلوں کو اسکین کریں جن کے آپ مجاز مالک ہیں۔ انکرپٹڈ .crypt* بیک اپ کو بغیر مجاز کلید کے ڈیکرپٹ نہیں کیا جاتا۔"
        ),
    },
}


def get_text(lang: str = "en") -> dict[str, Any]:
    """Return translation dictionary for `lang` ('en', 'hi', 'ur'), defaulting to English."""
    return TEXT.get(lang, TEXT["en"])
