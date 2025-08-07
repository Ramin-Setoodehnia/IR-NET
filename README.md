[English](README-EN.md)

<div dir="rtl">

<p align="center">
    <img src="https://img.shields.io/badge/Version-18-blue.svg" alt="Version">
    <img src="https://img.shields.io/badge/Platform-Ubuntu_22.04+-orange.svg" alt="Platform">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/github/stars/cy33r/IR-NET?style=social" alt="GitHub Stars">

<p align="center">
  <img src="https://github.com/user-attachments/assets/d668015f-bf34-4318-a5f0-0583d252bfd0" alt="IR-NET-Logo"/>
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
* بهینه ساز SYSCTL اختصاصی
* بهینه ساز QLEEN & MTU اختصاصی (ماندگار)
* رفع مشکل تاریخ واتس‌اپ
* بهینه سازی سرعت (TC)
* بهینه سازی بستر شبکه (پیشرفته و ماندگار)
* مدیریت و یافتن بهترین DNS
* یافتن سریعترین مخزن APT (پیشرفته)
* تست پکت لاست بین سرور (MTR)
* دی ان اس رفع تحریم داخلی


#### 🛡️ امنیت و دسترسی
* مدیریت فایروال و پینگ (UFW)
* مدیریت پینگ سرور (ICMP)
* مدیریت ورود کاربر ROOT
* تغییر پورت SSH
* تغییر پسوورد سرور
* جلوگیری از ابیوز (ABUSE DEFENDER)
* دستیار پنل X-UI (چند ادمین)
* ریستارت خودکار XRAY
* مدیریت ریبوت خودکار سرور
* فعال/غیرفعال کردن IPV6
* اسکنر پورت
* اسکنرهای بدافزار
* ممیزی امنیتی با LYNIS
* اسکن رنج وارپ پیشرفته
* اسکن رنج آروان کلود
* تشخیص سالم بودن آی پی
* اسکن اندپوینت های WARP

#### 👮‍♂️ ابزارهای مانیتورینگ و عیب یابی
* مانیتورینگ پیشرفته منابع (BTOP/HTOP)
* تحلیلگر فضای دیسک (NCDU)
* مشاهده زنده ترافیک شبکه (IFTOP)

#### 💻 ابزارهای سیستمی و مدیریتی
* مدیریت حافظه SWAP
* پاکسازی سیستم (آزاد کردن فضا)

#### 🛠 ابزارهای پیشرفته و وب
* نصب و مدیریت DOCKER
* مدیریت وب سرور CADDY (با SSL خودکار)
* مدیریت گواهی SSL با CERTBOT
* مسدودسازی بر اساس موقعیت جغرافیایی (GEO-IP)
  

#### 🚀 آپدیت و نصب پکیج های لازم

#### ⚙️ نصب / به‌روزرسانی پنل TX-UI هوشمند

#### ⚙️ نصب / به‌روزرسانی پنل 3X-UI هوشمند

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
