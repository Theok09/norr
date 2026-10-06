# NORR — مشکلات فعلی (2026-10-04)

تاییدشده با کد + تست زنده روی ir (94.183.218.24) ↔ ex2 (45.135.195.61).

## 🔴 بحرانی

### ۱. کار این session هنوز deploy نشده
باینری زنده روی هر دو سرور قدیمی است:
- ex2: deployed 13:11, built 13:42
- ir: deployed 13:12, built 13:39

یعنی روی سرورها **نیست**: obfuscation length-bucketing، spoof wiring، فیکس‌های امنیتی (DoS decode، CAP_NET_RAW drop، IP-ID). فقط camo-TLS fix زنده است. همه‌ی کار خوب روی git/disk مانده. **تا deploy نشود بی‌اثر است.**

### ۲. spoof از این سرور ایران غیرممکن — strict uRPF
تست زنده: از ir هر source جعلی (same-/24، foreign، unrelated) drop شد؛ فقط IP واقعی رد شد. ISP این سرور (papiliohost) egress filtering کامل دارد. کد spoof کامل و امن، ولی **شبکه نمی‌گذارد**. فقط با سرور ایران روی ISP با uRPF شُل حل می‌شود.

### ۳. REALITY در ایران شکسته
DPI ایران روی تکمیل TLS handshake RST-flood می‌زند و transcript را fingerprint می‌کند. راه‌حل = real TLS (شناسایی نمی‌شود) + obfuscation قوی، نه REALITY. camo الان همین کار را می‌کند (به real TLS سوئیچ شد).

## 🟡 مهم (کد)

### ۴. spoof end-to-end تست نشده
فقط unit-tested. چون این سرور drop می‌کند، datapath واقعی spoof اثبات نشده. روی سرور spoof-capable باید تست شود.

### ۵. سمت گیرنده spoof-receipt نیمه‌کاره
`kSpoofReceipt` frame + encode/decode هست، ولی:
- receiver که tally بزند کدام spoofed-source رسید → نیست.
- emit دوره‌ای receipt از ex2 → نیست.
- dispatch در worker (مثل kLossReport) → نیست.
عمداً نیمه — بی‌فایده تا سرور مناسب. feedback loop تا این کامل نشود واقعی نیست.

### ۶. CAP_NET_RAW در systemd unit نیست
کد قبل drop raw socket را باز می‌کند (با root). ولی اگر به‌صورت non-root service اجرا شود، unit باید `AmbientCapabilities=CAP_NET_RAW` داشته باشد. الان Type=forking via norr-quick (root)، پس کار می‌کند — ولی مستند/enforced نیست.

### ۷. scripts/ و bench/ در gitignore
خط ۱۷–۱۸. e2e scriptها و bench در git نیستند → clone/CI آنها را ندارد (مثل tests/ که فیکس شد). ۱۵ تست e2e که روی سرور fail شدند دقیقاً به همین خاطر بود.

### ۸. obfuscation بزرگ‌تر از ۱۴۷۲ بایت spoof را silently drop می‌کند
اگر payload + overhead از ۱۴۷۲ رد شود، spoof packet بی‌صدا می‌افتد. MTU تونل ۱۲۸۰–۱۳۸۰، پس در عمل نمی‌رسد — ولی diagnostic ندارد.

## 🟢 حل‌شده این session (committed، اکثرا deploy نشده)
- camo: ۰ → ۲۷۴ مگابیت (fake-TLS → real TLS).
- obfuscation junk-padding security bug + length-bucketing ضد size-fingerprint.
- spoof engine کامل: SpoofPool (HRW + quarantine، overflow-safe) + SpoofFeedback (peer-receipt + epoch re-roll) + SpoofEnvelope (BCP38 probe) + SpoofSender (IP_TRANSPARENT + sendmmsg).
- config transport.spoof_sources + validation.
- CAP_NET_RAW support + امنیت tight (drop post-open).
- ۲ gap امنیتی فیکس.
- tests/ در git (۴۷ فایل)، ۱۴ commit.

## 🟢 سالم (تست زنده)
- ۴ حامل زنده: udp 493، icmp 349، tcp 333، camo 274 مگابیت.
- ۴۷ تست unit pass.
- سرورها up، norr-doctor PASS.

## اولویت
1. **deploy** (obfuscation + fixes به هر دو سرور) — بزرگ‌ترین برد معطل.
2. scripts/ + bench/ از gitignore.
3. spoof-receipt سمت گیرنده (برای سرور spoof-capable آینده).
4. سرور ایران با uRPF شُل پیدا کن → spoof را واقعی تست کن.
