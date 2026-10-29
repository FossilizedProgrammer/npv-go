# npv-go

برنامه‌ای به Go که کانفیگ‌های export شده از اپ اندرویدی **NPV Tunnel V2raySSH**
(فایل‌های `.npvs`) را رمزگشایی می‌کند و به شما یک پراکسی محلی SOCKS5/HTTP می‌دهد.
موتور پروکسی، xray-core، به‌صورت کتابخانه داخل خود باینری اجرا می‌شود؛ هیچ اپ
خارجی (v2rayN، sing-box و…) لازم نیست.

نام فایل اهمیتی ندارد. شکل محتوا (پاکت قفل‌شده، پاکت باز، یا یک فایل متنی لینک)
از خودِ بایت‌ها تشخیص داده می‌شود، پس `VPN-2026.npvs`، `export.txt`، `1.npvs` یا
هر نام دیگری کار می‌کند. در مثال‌های پایین `example.npvs` را با نام فایل خودتان
جایگزین کنید.

## باینری آماده

از صفحه‌ی [Releases](https://github.com/FossilizedProgrammer/npv-go/releases) آرشیو
آماده را بردارید؛ گیتهاب خودش هر دو معماری را می‌سازد:

- `npv-linux-amd64.tar.gz`
- `npv-windows-amd64.zip`

```bash
tar -xzf npv-linux-amd64.tar.gz
./npv-linux-amd64/npv connect example.npvs
```

## ساخت

```bash
go build -o npv ./cmd/npv-go
```

بیلد فقط Go می‌خواهد: CGO لازم ندارد و همه‌ی فایل‌های جدول، لینک‌های کانفیگ و
موتور xray-core داخل خود باینری‌اند. پوشه‌ی `dist/` و باینری‌های ساخته‌شده در
`.gitignore` هستند.

## استفاده

پرچم‌ها را **قبل از نام فایل** بدهید (رفتار رایج بسته‌ی `flag` گو):

```bash
./npv connect        example.npvs                       # خودش سریع‌ترین کانفیگ زنده را پیدا می‌کند و وصل می‌شود
./npv list           example.npvs                       # فهرست کانفیگ‌های داخل فایل
./npv list -check    example.npvs                       # فقط کانفیگ‌های زنده، مرتب بر پایه سرعت
./npv serve -s 5     example.npvs                       # پراکسی روی ۱۲۷.۰.۰.۱:۱۰۸۰ و :۸۰۸۰
./npv serve -s 5 -socks 11080 -http 18080 example.npvs  # پورت‌ها را خودتان بدهید
./npv serve -s 5 -socks 127.0.0.1:1080 -http "" -log error example.npvs
./npv config -s 5    example.npvs                       # JSON تولیدشده برای xray را چاپ می‌کند
./npv decode  -o links.txt example.npvs                 # فقط لینک‌های رمزگشایی‌شده
```

مثال کامل، با یک فایل واقعی:

```bash
./npv connect -socks 11080 -http 18080 ~/Downloads/example.npvs
```

- `-s` شماره‌ی کانفیگ (از ۱) یا بخشی از remark آن است؛ مثلاً `-s configraygan-27`.
- `-pass` برای کانفیگ‌هایی که قفل رمز عبوری‌اند (اگر export با passphrase ساخته
  شده باشد، کلید اپ کافی نیست و باید همان رمز را داشته باشید).
- خروجی `list` ترنسپورت هر کانفیگ را هم نشان می‌دهد (`tcp/reality`، `ws/tls`، …).
- اگر هیچ کانفیگی از فایل درنیاید، همان اول می‌ایستد: خطوطی که لینک نیستند (مثل
  آدرس کانال تلگرام که بعضی exportها در سرِ فایل می‌گذارند) با
  `skipping entry N: …` رد می‌شوند و در آخر `no usable configs` می‌خوانید. اگر
  فایل اصلاً شبیه هیچ‌کدام از شکل‌های شناخته‌شده نباشد، خطای همان رمزگشا را
  می‌بینید (مثلاً `/tmp/bad.txt: too short: 20 bytes`).

### بندهای SOCKS5 و HTTP

`-socks` و `-http` سه شکل را می‌پذیرند و در `serve` و `connect` یکی هستند:

```bash
./npv serve -s 5 -socks 11080 -http 18080 example.npvs         # فقط پورت => 127.0.0.1
./npv serve -s 5 -socks 0.0.0.0:11080 -http "" example.npvs    # روی همه‌ی interfaceها
./npv connect -socks "[::1]:11080" -http 18080 example.npvs    # IPv6 loopback
```

- پورتِ تنها (`11080`) یعنی `127.0.0.1:11080`؛ برای دسترسی از بیرونِ همین
  سیستم صریح `0.0.0.0:port` بنویسید (پراکسی بدون رمز روی interface عمومی امن
  نیست).
- `-http ""` آن listener را خاموش می‌کند؛ اگر هر دو خاموش باشند برنامه با خطا
  می‌ایستد.
- آدرس بد (`abc`، `0`، `65536`) و پورتِ اشغال‌شده **قبل از هر کاری** گزارش
  می‌شوند، نه بعد از ۴۰ ثانیه سنجش: `-socks address 127.0.0.1:1080 is already
  in use; pick another port with -socks or stop whatever holds it`.

### وصل شدن خودکار

`connect` همان سنجش را خودش انجام می‌دهد و نیازی به `-s` ندارد:

```bash
./npv connect example.npvs
./npv connect -timeout 5s -samples 2 -jobs 6 example.npvs           # سنجش سریع‌تر
./npv connect -socks 127.0.0.1:1080 -http "" -log error example.npvs
```

ترتیب کار: همه‌ی کانفیگ‌ها را با یک درخواست واقعی می‌سنجد، سه تا از سریع‌ترین
زنده‌ها را چاپ می‌کند و بعد روی سریع‌ترینشان listener باز می‌کند تا Ctrl-C. اگر
هیچ‌کدام جواب ندهد با پیام «none of the configs answered» بیرون می‌آید.

- پرچم‌های سنجش (`-timeout`، `-samples`، `-jobs`، `-url`) و پرچم‌های listener
  (`-socks`، `-http`، `-log`) را می‌پذیرد؛ `-s` و `-check` را نادیده می‌گیرد.
- `-log` در `connect` پیش‌فرض `none` است (در `serve` پیش‌فرض `warning`). دلیلش
  این است که لاگر xray سراسری است و نمونه‌های موقتِ سنجش هم از همان لاگر
  می‌نویسند؛ بدون `none` چند خط `[Error] websocket ...` از کانفیگ‌های مُرده‌ای که
  همین الان سنجیده شدند، زیر سرورِ انتخاب‌شده چاپ می‌شد و شبیه خرابیِ آن به‌نظر
  می‌رسید. برای دیدن لاگ xray: `./npv connect -log warning …`.
- رتبه‌ها یک snapshot هستند. اگر تونل بعداً قطع شد، Ctrl-C بزنید و دوباره
  اجرایش کنید تا کانفیگ را عوض کند.
- بین سنجش و سرویس‌دادن یک مکث ~۲ ثانیه‌ای هست تا dialهای نیمه‌کاره‌ی سنجش
  تمام شوند؛ این مکث زمانی اثرش را نشان می‌دهد که `-log` را صریح روشن کرده باشید.

### فهرست فقط زنده‌ها، به ترتیب سرعت

`list -check` هر کانفیگ را موقتاً بالا می‌آورد، از آن یک درخواست
`generate_204` می‌زند و زمان میانی (median سه نمونه) را اندازه می‌گیرد:

```bash
./npv list -check example.npvs                        # زنده‌ها، سریع‌ترین در بالا
./npv list -check -all example.npvs                   # به‌علاوه دلیل مرده‌ها
./npv list -check -timeout 6s -samples 5 -jobs 6 example.npvs
./npv list -check -url http://example.com example.npvs   # هدف تست را عوض کند
```

پرچم‌ها: `-all` (نمایش مرده‌ها با دلیل خطا)، `-timeout` (مهلت هر درخواست، پیش‌فرض
`10s`)، `-samples` (تعداد درخواست برای هر کانفیگ، میانش را گزارش می‌کند، پیش‌فرض
۳)، `-jobs` (چند کانفیگ همزمان سنجیده شود، پیش‌فرض ۳) و `-url` (هدف تست؛ اگر
خالی باشد از چند آدرس `generate_204` یکِ قابل‌دسترس را خودش انتخاب می‌کند).

### خروجی JSON برای رابط‌های گرافیکی

`list -json` به‌جای جدول، یک شیء JSON روی stdout می‌ریزد (همه در یک خط) تا
برنامه‌های دیگر لازم نباشد متن جدول را پارسه کنند:

```bash
./npv list -json example.npvs           # فقط فهرست، بدون داوری
./npv list -check -json example.npvs    # همان فهرست + median و دلیل خطا
```

شکل خروجی (این‌جا خوانایی‌دار شده):

```json
{
  "creatorMessage": "...",
  "checked": true,
  "total": 31,
  "answered": 12,
  "servers": [
    {"index": 30, "remark": "configraygan-2", "proto": "ss", "kind": "v2ray",
     "transport": "tcp/none", "ok": true, "medianMs": 406},
    {"index": 1, "remark": "configraygan-31", "proto": "ss", "kind": "v2ray",
     "transport": "tcp/none", "ok": false,
     "error": "Get \"https://www.gstatic.com/generate_204\": context deadline exceeded"}
  ]
}
```

- `checked` می‌گوید داوری از `-check` آمده یا نه. بدون `-check` همهٔ `ok`ها
  `false` است و هیچ کانفیگی مردده حساب نمی‌شود؛ فقط `error` و `medianMs` ندارند.
- ترتیب `servers` همان ترتیب خروجیِ چک است: زنده‌ها سریع‌ترین به قبل، بعد
  مرده‌ها با دلیل خطا.
- خطاها و لاگ‌ها روی stderr می‌مانند، پس stdout همیشه یک JSON سالم است.
پراکسی‌های محلی روی پورت‌های تصادفی باز می‌شوند و بلافاصله بسته می‌شوند؛ چیزی
روی ۱۰۸۰ یا ۸۰۸۰ نمی‌ماند.

این جدول یک snapshot است: سرورهای عمومی این کانفیگ‌ها اغلب دقایقی بعد از جواب
دادن قطع می‌شوند. اگر کانفیگی در `-check` سبز شد ولی بعداً کار نکرد، دوباره
اجرایش کنید تا رتبه‌ها به‌روز شوند.

استفاده با پراکسی:

```bash
curl -x http://127.0.0.1:8080  https://api.ipify.org
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

### فایل‌هایی که `.npvs` نیستند

سه شکل ورودی پذیرفته می‌شود، بدون توجه به نام و پسوند:

| محتوا | چه اتفاقی می‌افتد |
| --- | --- |
| پاکت قفل‌شده‌ی نسل ۱ یا نسل ۲ اپ | با کلید سفیدکربله‌ی خود اپ (و `-pass` اگر لازم باشد) باز می‌شود. |
| پاکت بازِ اپ (`NPVO1…`) | بدون رمز خوانده و به لینک تبدیل می‌شود. |
| متن ساده‌ی لیست لینک‌ها (`vless://`، `trojan://`، `ss://`، `vmess://`، `ssh://`) | همان‌طور استفاده می‌شود؛ جایگزین کامل `.npvs` است. |

## چطور کار می‌کند

| لایه | کار |
| --- | --- |
| `internal/npvs` | باز کردن پاکت `NPVS`: رمزگشایی AEAD (ChaCha20-Poly1305)، PBKDF2 برای passphrase، و کلید سفیدکربله‌ی (whitebox) نسل ۲ اپ که از assets همان اپ استخراج شده. |
| `internal/proxy/outbound.go` | نگاشت پارامترهای لینک اشتراک (`type`, `security`, `sni`, `fp`, `pbk`, `sid`, `path`, `host`, …) به `streamSettings` ایکس‌ری. |
| `internal/proxy/engine.go` | ساخت کانفیگ کامل، بالا بردن xray درون همان پروسه (`core.New` + `Start`) و باز کردن inboundهای SOCKS5/HTTP. |
| `internal/proxy/ssh.go` | کانفیگ‌های `ssh://`، چون xray خروجی SSH ندارد. |

پشتیبانی پروتکل‌ها: `vless` (شامل reality و xtls-rprx-vision)، `trojan`، `ss`،
`vmess`؛ ترنسپورت‌های `tcp`، `ws`، `grpc`، `kcp`، `httpupgrade`، `xhttp`.

## محدودیت‌ها

- **SSH**: خود اپ SSH را در کتابخانه‌ی Go داخلش (fork از sing-box) پیاده می‌کند و
  یک forward از نوع `direct-tcpip` می‌سازد. آنچه export (`ssh://…`) حمل می‌کند
  فقط host/port/user/pass/`sshConfigType`/`httpProxy`/`payload` است؛ فیلدهایی مثل
  `sni`، `tlsVersion`، `sshPrivateKey` و تنظیمات DNSTT در خود بسته نیستند. برای
  همین `SSH-Direct` کار می‌کند ولی نوع‌های `SSH-TLS*`، `SSH-Proxy*`، `SSH-Payload*`
  و `SSH-DNSTT` یا کلید-خصوصی قابل بازسازی نیستند. در حالت SSH فقط TCP فوروارد
  می‌شود (UDP و `payload` نادیده گرفته می‌شوند) و listener HTTP فعال نیست.
- ترافیک کاملاً از تونل می‌رود؛ هیچ قانون routing برای عبور مستقیم IPهای خصوصی
  اضافه نشده است.
- بیشتر کانفیگ‌های عمومی که در تلگرام پخش می‌شوند مرده‌اند: در نمونه‌ای که موقع
  توسعه با آن کار کردیم (`BOMB.npvs`، ۳۱ کانفیگ) ۱۴ تا زنده بودند. بعضی هم خودِ
  export خراب است؛ مثلاً در لینک
  `vless://XpnTeam-59@199.232.78.160…` جای uuid یک نام کاربری نشسته، پس سرور آن
  را رد می‌کند. عددِ زنده‌ها با هر فایل و هر بار اجرا فرق می‌کند؛ برای همین
  `list -check` و `connect` هست.
- ایکس‌ری رسمی دیگر فیلدهای قدیمی `kcpSettings.header` و `seed` را نمی‌پذیرد
  (خطای «feature removed» می‌دهد) ولی کانفیگ‌های kcp همین اپ همان‌ها را دارند؛
  برای همین وابستگی به fork `patterniha/Xray-core` replace شده (توضیحش در
  `go.mod`). این fork جلوتر از نسخه‌ی رسمی است و آن فیلدها را نگه داشته. اگر
  می‌خواهید با ایکس‌ری رسمی بسازید، خط `replace` را حذف کنید.

## تست

```bash
go test ./...
```

تست‌ها رمزگشایی نمونه‌ی واقعی (`internal/npvs/testdata/BOMB.npvs` — فقط یک fixture
با نام دلخواه)، بازگردانی لینک‌ها به outbound، و پارس `ssh://` را می‌سنجند.
`config_test.go` هر کانفیگ تولیدشده (شامل تک‌تک کانفیگ‌های همان fixture) به خودِ
xray می‌دهد (`serial.LoadJSONConfig` + `core.New`)؛ همین تست جایی بود که ثابت
کرد outbound تروجان آدرس/پورت ندارد و xray آن را رد می‌کند.
