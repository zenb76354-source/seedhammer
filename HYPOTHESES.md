# SeedHammer 🔨 — دليل الفرضيات الكامل

GPU Bitcoin private key generator.
SHA256(seed) → 32-byte key. No ECC, no verification.

## Modes

### H36 — Timestamp milliseconds
```
./seedhammer --mode h36 --start <ms> --count <N> --out keys.bin
```
- **المنطق**: ms → 8 bytes BE → SHA256
- **النطاق**: كل ملي ثانية من 2009-01-01 إلى 2012-01-01
- **العدد**: 94,675,968,000 (~94.6B)
- **أمر التشغيل**:
```bash
./seedhammer --mode h36 --start 1230768000000 --count 94675968000 --out keys_h36.bin
```
- **لماذا**: timestamp ms بيّن أن التطبيقات الأولى لـ Bitcoin (Bitcoind, Bitcoin-QT) استخدمت time(NULL) لتوليد المفاتيح. ms يغطي الـ ثواني + اختلافات توقيت millisecond.

### H36-micro — Timestamp microseconds
```
./seedhammer --mode h36-micro --start <us> --count <N> --out keys.bin
```
- **المنطق**: us → 8 bytes BE → SHA256
- **العدد**: 94.6 تريليون
- **متى نستخدمه**: إذا فشل H36، تحسّساً من تطبيقات استخدمت gettimeofday() (دقة ميكروثانية)

### H36-nano — Timestamp nanoseconds (مرجعي فقط)
- **غير قابل للتشغيل عملياً**: 94.6 كوادريليون
- فقط للتوثيق: إذا أشارت أدلة جنائية إلى استخدام high_resolution_clock

### H36-combo — ms + PID
```
./seedhammer --mode h36-combo --start <ms> --pid-count 65536 --count <N> --out keys.bin
```
- **المنطق**: ms(8) ++ pid(4) → SHA256
- **العدد**: 94.6B × 65536 = 6.2 كوادريليون
- **لماذا**: بعض المبرمجين خلطوا PID مع الوقت لـ "زيادة العشوائية"

---

### H28 — Sequential integers (uint32)
```
./seedhammer --mode h28 --start 0 --count 10000000000 --out keys_h28.bin
```
- **المنطق**: i → 4 bytes BE → SHA256
- **النطاق**: 0 → 10,000,000,000 (10B)
- **لماذا**: المبرمجون استخدموا أعداد متسلسلة (0, 1, 2...) كمفاتيح

### H48 — Big integers (uint48)
```
./seedhammer --mode h48 --start 0 --count 281474976710656 --out keys_h48.bin
```
- **المنطق**: i → 6 bytes BE → SHA256
- **النطاق**: 0 → 2^48 (281 تريليون)
- **لماذا**: بعض المبرمجين استخدموا أعداد أكبر (48-bit) لـ "زيادة الأمان"

### H20 — srand(time(NULL)) + rand() (little-endian)
```
./seedhammer --mode h20 --start 1230768000 --count 94675968 --out keys_h20.bin
```
- **المنطق**: time_t → 4 bytes LE → SHA256 (Little-Endian، تم توحيد الوصف مع التنفيذ)
- **النطاق**: 2009-01-01 إلى 2012-01-01 (كل ثانية)
- **العدد**: 94,675,968
- **لماذا**: تطبيقات C++ قديمة استخدمت srand(time(NULL)) ثم rand() للأرقام العشوائية

### H03 — Timestamp + PID
```
./seedhammer --mode h03 --ts <timestamp> --pid-count 65536 --out keys_h03.bin
```
- **المنطق**: ts(4) ++ pid(4) → SHA256
- **النطاق**: كل ثانية في 2009-2012 × كل PID (0-65535)
- **العدد**: 94M × 65536 = ~6.2 تريليون

للثواني كلها:
```bash
# نطاق كامل 2009-2012 عبر سكريبت
```

### H09 — Word + year
```
./seedhammer --mode h09 --dict phrases.txt --year-start 2008 --year-end 2024 --out keys_h09.bin
```
- **المنطق**: word + year → SHA256
- **النطاق**: 2008-2024 (17 سنة)
- **لماذا**: نمط شائع لـ brainwallet: "bitcoin2009", "password2010"...

### H34 — Full datetime strings
```
./seedhammer --mode h34 --ts-start 1268728843 --ts-end 1284608803 --out keys_h34.bin
```
- **المنطق**: timestamp → نص بصيغ متعددة (ISO, RFC, ordinal...) → SHA256
- **النطاق**: كل ثانية 2010-2011
- **عدد الصيغ**: 31 مليون

### H37 — Timestamp multi-format
```
./seedhammer --mode h37 --start <ts> --count <N> --out keys_h37.bin
```
- **المنطق**: timestamp بـ 4 صيغ (4-byte LE, 8-byte LE, 4-byte BE, 8-byte BE) → SHA256
- **العدد**: 4 لكل timestamp

### H24 — JavaScript PRNG
```
./seedhammer --mode h24 --start <seed> --count <N> --engine v8 --out keys_h24.bin
```
- **المحركات**: V8 (XorShift128+), SpiderMonkey (LCG), JavaScriptCore (MWC1616) (تمت إضافة دعم SpiderMonkey و JavaScriptCore)
- **لماذا**: محافظ Bitcoin.js استخدمت Math.random() الذي يختلف حسب المحرك
- **النطاق**: 30M+ حسب المحرك

### H23 — PHP mt_rand()
```
./seedhammer --mode h23 --start 0 --count 4294967296 --out keys_h23.bin
```
- **المنطق**: mt_srand(seed) → mt_rand() لكل 32-bit seed
- **النطاق**: 4.3 مليار
- **لماذا**: بعض تطبيقات الويب استخدمت mt_rand() ضعيفة

### H07 — Android SecureRandom
```
./seedhammer --mode h07 --start 0 --count 40000000 --out keys_h07.bin
```
- **المنطق**: SHA256(مخرج Android SecureRandom) لكل بذرة شائعة
- **النطاق**: 40M key

---

## Quick Reference — أمر تشغيل كل فرضية

| الفرضية | الأمر |
|:-------:|:------|
| H36 | `--mode h36 --start 1230768000000 --count 94675968000` |
| H36-micro | `--mode h36-micro --start 1230768000000000 --count 94675968000000` |
| H28 | `--mode h28 --start 0 --count 10000000000` |
| H48 | `--mode h48 --start 0 --count 281474976710656` |
| H20 | `--mode h20 --start 1230768000 --count 94675968` |
| H03 | `--mode h03 --ts <N> --pid-count 65536` |
| H09 | `--mode h09 --dict phrases.txt --year-start 2008 --year-end 2024` |
| H34 | `--mode h34 --ts-start 1268728843 --ts-end 1284608803` |
| H37 | `--mode h37 --start 1230768000 --count 94675968` |
| H24 | `--mode h24 --seed 0 --count 30000000 --engine v8` |
| H24-sm | `--mode randstorm_sm --start 0 --count 30000000` |
| H24-jsc | `--mode randstorm_jsc --start 0 --count 30000000` |
| H23 | `--mode h23 --start 0 --count 4294967296` |
| H07 | `--mode h07 --start 0 --count 40000000` |
