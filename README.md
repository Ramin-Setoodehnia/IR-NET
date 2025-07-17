[English](README-EN.md)

<div dir="rtl">

<p align="center">
    <img src="https://img.shields.io/badge/Version-13-blue.svg" alt="Version">
    <img src="https://img.shields.io/badge/Platform-Ubuntu_22.04+-orange.svg" alt="Platform">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/github/stars/cy33r/IR-NET?style=social" alt="GitHub Stars">

<p align="center">
  <img src="https://github.com/user-attachments/assets/a75022b0-0f79-4f77-9c61-039f875a9bdb" alt="IR-NET-Logo"/>
</p>

<h1 align="center">IR-NET - مجموعه ابزار مدیریت سرور اوبونتو</h1>

<p align="center">
یک اسکریپت قدرتمند و ماژولار با رابط کاربری متنی (TUI) برای مدیریت، بهینه‌سازی و امن‌سازی سرورهای لینوکس اوبونتو که با تمرکز بر نیازهای کاربران ایرانی طراحی شده است.
</p>

---

## 🚀 نصب و راه‌اندازی

برای اجرای این مجموعه ابزار، **یکی از دو دستور زیر** را در ترمینال سرور خود کپی و اجرا کنید.

**روش ۱ (اصلی):**
```bash
snap install jq
```
```bash
bash <(curl -sL "https://raw.githubusercontent.com/cy33r/IR-NET/main/MENU-FA.sh?$(date +%s)")
```
```bash
bash <(curl -sL "https://raw.githubusercontent.com/cy33r/IR-NET/main/MENU-EN.sh?$(date +%s)")
```

**روش ۲ (جایگزین با CDN):**


---
> **روش جایگزین (آفلاین):**
>
> 1.  فایل‌ `MENU-FA.sh` یا `MENU-EN.sh` را دانلود کنید.
> 2.  فایل‌ دانلود شده را در پوشه‌ی `/root` سرور آپلود نمایید.
> 3.  دستورات زیر را به ترتیب در ترمینال اجرا کنید:
>
> ```bash
> chmod +x /root/MENU-FA.sh
> sed -i 's/\r$//' /root/MENU-FA.sh
> sudo bash /root/MENU-FA.sh
> ```
>
> ```bash
> chmod +x /root/MENU-EN.sh
> sed -i 's/\r$//' /root/MENU-EN.sh
> sudo bash /root/MENU-EN.sh
> ```
**سیستم‌عامل مورد نیاز:** این اسکریپت به طور اختصاصی برای توزیع **UBUNTU 22.04 و بالاتر** طراحی شده است.

---

## ✨ قابلیت‌ها

`ایرنت` یک جعبه ابزار کامل است که وظایف پیچیده مدیریت سرور را در قالب منوهای ساده ارائه می‌دهد:

#### 🌐 بهینه سازی شبکه و اتصال
* مدیریت بهینه سازهای TCP (BBR, HYBLA, CUBIC)
* قابلیت خاموش و روشن کردن پینگ سرور
* رفع مشکل تاریخ واتس‌اپ
* بهینه سازی سرعت (TC)
* بهینه سازی بستر شبکه (پیشرفته)
* مدیریت و یافتن بهترین DNS
* یافتن سریعترین مخزن APT (پیشرفته)
* تست پینگ سرورهای DNS
* پینگ خارج به داخل
* پینگ داخل به خارج
* ست پکت لاست بین سرور (MTR)
* تست سرعت خودکار ایران و خارج (IPERF3)
* دی ان اس رفع تحریم داخلی

#### 🛡️ امنیت و دسترسی
* مدیریت فایروال (UFW)
* مدیریت ورود کاربر روت
* تغییر پورت SSH
*  ریستارت خودکار XRAY
* مدیریت ریبوت خودکار سرور
* فعال/غیرفعال کردن IPV6
* اسکنر پورت
* اسکن رنج آروان کلود
* تشخیص سالم بودن آی پی
* اسکن اندپوینت های WARP

#### 🚀 آپدیت و نصب پکیج های لازم

#### ⌛️ نصب آفلاین پنل TX-UI
* نصب پنل از فایل موجود در سرور
* راهنمای نصب آفلاین

#### ⚙️ تانل ایرنت (IRNET TUNNEL)
* پروتکل H2 (استاندارد و سریع)
* پروتکل QUIC (پایداری بیشتر در شبکه ضعیف)
* پروتکل VLESS (حالت پنهان‌کاری، نیاز به دامنه)

#### 💎 تانل رت هول بهینه ایران
* نصب تونل RATHOLE (با اسکریپت اصلی)
* بهینه ساز و مونیتورینگ RATHOLE
* راهنما

## 🏞️ تصاویری از محیط اسکریپت

<details>
  <summary><b>🖼️ برای مشاهده تصاویر، اینجا کلیک کنید</b></summary>
  <br>
  <p align="center">
    <img src="https://github.com/user-attachments/assets/0938de54-154e-4b61-9452-b759f02f7d5e" alt="IR-NET-Logo" width="70%"/>
    <br><br>
    <img src="https://github.com/user-attachments/assets/bb6c4406-28ab-461d-93f5-d4789ccafcb4" alt="IR-NET-Logo" width="70%"/>
    <br><br>
    <img src="https://github.com/user-attachments/assets/6cb7f68f-fe97-4e88-8813-43a81dc8f242" alt="IR-NET-Logo" width="70%"/>
    <br><br>
    <img src="https://github.com/user-attachments/assets/ca9df664-4441-4bc4-8f3e-aa2a6d07e82b" alt="IR-NET-Logo" width="70%"/>
  </p>
</details>

---
## 🤝 مشارکت و نویسندگان
هرگونه مشارکت، گزارش مشکل (Issue) و پیشنهاد برای قابلیت‌های جدید مورد استقبال قرار می‌گیرد. می‌توانید مشکلات و پیشنهادات خود را در بخش [Issues](https://github.com/cy33r/IR-NET/issues) این ریپازیتوری ثبت کنید.

* **CREATOR:** AMIR ALI KARBALAEE ([T.ME/CY3ER](https://t.me/CY3ER))
* **COLLABORATOR:** FREAK ([T.ME/FREAK_4L](https://t.me/FREAK_4L))
* **COLLABORATOR:** IRCFSPACE ([T.ME/IRCFSPACE](https://t.me/IRCFSPACE))

---

## 🎁 DONATION / حمایت مالی
<br>
اگر این پروژه برای شما مفید بوده است، می‌توانید از ما حمایت مالی کنید.

**TRON (TRX)**
```
TBwGy36S9AV7iXFukdC8Y94zQZhQndPJyD
```

**TETHER (USDT) - BEP20**
```
0xC69fa0FecB4c76d89813dA6BC64827Db399B73f6
```

## ⚖️ مجوز انتشار
این پروژه تحت مجوز MIT منتشر شده است.

</div>
