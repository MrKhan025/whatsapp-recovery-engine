TEXT = {
 "en": {"title":"WhatsApp Recovery Engine","scan":"Scan folder","privacy":"Files stay on this device."},
 "hi": {"title":"व्हाट्सऐप रिकवरी इंजन","scan":"फ़ोल्डर स्कैन करें","privacy":"फ़ाइलें इसी डिवाइस पर रहती हैं।"},
 "ur": {"title":"واٹس ایپ ریکوری انجن","scan":"فولڈر اسکین کریں","privacy":"فائلیں اسی ڈیوائس پر رہتی ہیں۔"}
}
def get_text(lang="en"):
    return TEXT.get(lang, TEXT["en"])
