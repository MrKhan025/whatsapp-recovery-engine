"""Multi-language internationalization (`wtk/i18n.py`) for English, Hindi, and Urdu."""

from __future__ import annotations

from typing import Any

TEXT: dict[str, dict[str, str]] = {
    "en": {
        "dir": "ltr",
        "title": "WhatsApp Recovery Engine",
        "subtitle": "Offline-First Backup Analysis, Chat Inspection, Media Discovery & SHA-256 Verification",
        "scan": "Scan Folder",
        "load_sample": "Load Sample Data",
        "privacy": "Files stay on this device. 100% read-only local processing.",
        "nav_overview": "Overview",
        "nav_chat": "Chat Analyzer",
        "nav_backup": "Backup Analyzer",
        "nav_media": "Media Recovery",
        "nav_duplicates": "Duplicate Finder",
        "nav_verify": "Recovery Verification",
        "nav_reports": "Recovery Reports",
        "nav_settings": "Settings",
        "kpi_files": "Files Scanned",
        "kpi_media": "Accessible Media",
        "kpi_backups": "Backup Candidates",
        "kpi_dupes": "Duplicate Groups",
        "readiness_title": "Recovery Readiness Assessment",
        "disclaimer": (
            "Only scan files you own or are authorized to inspect. Encrypted .crypt* backups are never decrypted. "
            "Deleted messages cannot be recovered unless present in an accessible source."
        ),
    },
    "hi": {
        "dir": "ltr",
        "title": "व्हाट्सऐप रिकवरी इंजन",
        "subtitle": "ऑफ़लाइन बैकअप विश्लेषण, चैट निरीक्षण, मीडिया खोज और SHA-256 सत्यापन",
        "scan": "फ़ोल्डर स्कैन करें",
        "load_sample": "नमूना डेटा लोड करें",
        "privacy": "फ़ाइलें इसी डिवाइस पर रहती हैं। 100% रीड-ओनली लोकल प्रोसेसिंग।",
        "nav_overview": "अवलोकन (Overview)",
        "nav_chat": "चैट विश्लेषक",
        "nav_backup": "बैकअप विश्लेषक",
        "nav_media": "मीडिया रिकवरी",
        "nav_duplicates": "डुप्लिकेट खोजक",
        "nav_verify": "रिकवरी सत्यापन",
        "nav_reports": "रिकवरी रिपोर्ट",
        "nav_settings": "सेटिंग्स",
        "kpi_files": "स्कैन की गई फ़ाइलें",
        "kpi_media": "उपलब्ध मीडिया",
        "kpi_backups": "बैकअप फ़ाइलें",
        "kpi_dupes": "डुप्लिकेट समूह",
        "readiness_title": "रिकवरी तत्परता मूल्यांकन",
        "disclaimer": (
            "केवल उन्हीं फ़ाइलों को स्कैन करें जिनके आप स्वामी हैं। एन्क्रिप्टेड .crypt* बैकअप डिक्रिप्ट नहीं किए जाते हैं। "
            "हटाए गए संदेश तब तक पुनर्प्राप्त नहीं किए जा सकते जब तक वे किसी सुलभ स्रोत में मौजूद न हों।"
        ),
    },
    "ur": {
        "dir": "rtl",
        "title": "واٹس ایپ ریکوری انجن",
        "subtitle": "آف لائن بیک اپ تجزیہ، چیٹ معائنہ، میڈیا دریافت اور SHA-256 تصدیق",
        "scan": "فولڈر اسکین کریں",
        "load_sample": "نمونہ ڈیٹا لوڈ کریں",
        "privacy": "فائلیں اسی ڈیوائس پر رہتی ہیں۔ مکمل طور پر لوکل اور محفوظ پروسیسنگ۔",
        "nav_overview": "جائزہ",
        "nav_chat": "چیٹ تجزیہ کار",
        "nav_backup": "بیک اپ تجزیہ کار",
        "nav_media": "میڈیا ریکوری",
        "nav_duplicates": "ڈپلیکیٹ تلاش",
        "nav_verify": "ریکوری تصدیق",
        "nav_reports": "ریکوری رپورٹس",
        "nav_settings": "ترتیبات",
        "kpi_files": "اسکین شدہ فائلیں",
        "kpi_media": "دستیاب میڈیا",
        "kpi_backups": "بیک اپ فائلیں",
        "kpi_dupes": "ڈپلیکیٹ گروپس",
        "readiness_title": "ریکوری تیاری کا جائزہ",
        "disclaimer": (
            "صرف ان فائلوں کو اسکین کریں جن کے آپ مجاز مالک ہیں۔ انکرپٹڈ .crypt* بیک اپ کو ڈیکرپٹ نہیں کیا جاتا۔ "
            "حذف شدہ پیغامات اس وقت تک بحال نہیں ہو سکتے جب تک وہ کسی قابل رسائی بیک اپ میں موجود نہ ہوں۔"
        ),
    },
}


def get_text(lang: str = "en") -> dict[str, Any]:
    """Return translation dictionary for `lang` ('en', 'hi', 'ur'), defaulting to English."""
    return TEXT.get(lang, TEXT["en"])
