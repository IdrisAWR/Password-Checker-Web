# Pass-Q — Password Strength Checker & Generator

Aplikasi web statis untuk menguji kekuatan password dan membuat password acak yang aman.
Seluruh logika berjalan di browser. Tidak ada backend, tidak ada penyimpanan data.

> Demo: https://passq-checker.vercel.app/

## Fitur

- **Analisis real-time**: perkiraan entropi, estimasi waktu bobol, dan skor lima tingkat.
- **Deteksi pola lemah**: password umum, kata umum (termasuk versi leetspeak seperti `p@ssw0rd`), karakter berulang, urutan (`abc`, `1234`), jalur keyboard (`qwerty`, `asdf`), dan tahun.
- **Cek kebocoran** lewat API Have I Been Pwned dengan metode **k-anonymity** (password tidak pernah dikirim).
- **Generator** berbasis `crypto.getRandomValues` dengan rejection sampling (tanpa modulo bias), opsi jenis karakter, dan opsi menghindari karakter yang mirip.
- **Content Security Policy** ketat lewat tag meta, tanpa inline script/style dan tanpa `innerHTML`.
- Tampilan terang/gelap: mengikuti pengaturan sistem, bisa diganti lewat tombol di header (tidak disimpan). Memakai font sistem agar CSP tetap ketat.
- Aksesibel: label form, `aria-live` untuk hasil, navigasi keyboard.

## Menjalankan

Web Crypto API (`crypto.subtle`) butuh konteks aman, jadi jalankan lewat server lokal, bukan dengan membuka file langsung:

```bash
python -m http.server 8000
# buka http://localhost:8000
```

## Struktur

```
index.html        halaman
style.css         gaya (tema terang/gelap)
script.js         logika analisis, generator, UI
logo-passq.png    logo dan favicon
fonts/            Plus Jakarta Sans dan JetBrains Mono (self-hosted, lisensi OFL)
vercel.json       header keamanan dan cache untuk Vercel
```

## Deploy ke Vercel

Proyek ini statis, tanpa build step.

1. Push repo ke GitHub.
2. Di Vercel: **Add New > Project**, pilih repo ini.
3. Framework Preset: **Other**. Kosongkan Build Command dan Output Directory, lalu Deploy.

`vercel.json` menambahkan header CSP (termasuk `frame-ancestors 'none'`), `X-Content-Type-Options`, `Referrer-Policy`, dan cache panjang untuk font. Vercel memakai HTTPS otomatis sehingga `crypto.subtle` berfungsi.

## Cara kerja

### Estimasi entropi

```
bit = panjang_efektif x log2(ukuran_pool_karakter)
```

- **Pool karakter** dihitung dari jenis karakter yang dipakai (a-z = 26, A-Z = 26, angka = 10, simbol = 33).
- **Panjang efektif** adalah panjang password dikurangi karakter yang "dimakan" pola. Misalnya `aaaa` hanya dihitung sebagai 1 karakter informasi, dan satu kata umum dihitung sekitar 2 karakter acak (setara kurang lebih 13 bit).
- Password yang persis sama dengan daftar umum dibatasi maksimal 10 bit.

### Estimasi waktu bobol

Mengasumsikan serangan offline pada hash cepat dengan 10 miliar tebakan per detik, dan penyerang rata-rata menemukan password setelah mencoba separuh ruang kemungkinan: `2^(bit-1) / 10^10` detik. Hash lambat seperti Argon2 atau bcrypt membuat angka sebenarnya jauh lebih besar.

### Cek kebocoran dengan k-anonymity

1. Browser menghitung SHA-1 dari password.
2. Hanya **5 karakter pertama** hash dikirim ke `api.pwnedpasswords.com/range/{prefix}`.
3. Server membalas ratusan sufiks hash yang cocok dengan prefix itu (ditambah padding via header `Add-Padding`).
4. Pencocokan sufiks lengkap dilakukan **lokal** di browser.

Server tidak pernah menerima password maupun hash lengkapnya. Pengecekan hanya berjalan saat tombol ditekan, tidak otomatis setiap ketikan.

## Keputusan keamanan

| Ancaman | Mitigasi |
|---|---|
| Password bocor ke server/pihak ketiga | Tidak ada backend; HIBP memakai k-anonymity dan hanya dipanggil atas permintaan pengguna |
| XSS | CSP `default-src 'none'`, `script-src 'self'`, tanpa inline script, semua output lewat `textContent` |
| Eksfiltrasi data lewat request liar | `connect-src` hanya mengizinkan `api.pwnedpasswords.com` |
| Kebocoran lewat header Referer | `referrer` meta dan `referrerPolicy: no-referrer` |
| Password generator yang bias/bisa diprediksi | `crypto.getRandomValues` + rejection sampling + shuffle Fisher-Yates (bukan `Math.random`) |
| Password tersimpan di autofill/riwayat | `autocomplete="off"`, tidak ada penyimpanan di localStorage/cookie |

## Batasan

- Estimasi entropi adalah **heuristik**, bukan jaminan. Library seperti zxcvbn punya kamus jauh lebih besar dan model yang lebih canggih.
- Daftar kata umum di sini sengaja kecil agar mudah dibaca dan dipahami.
- CSP via tag meta tidak mendukung `frame-ancestors`; karena itu `vercel.json` mengirim CSP lewat header HTTP. Di hosting lain, set header yang sama.
- Seseorang yang punya akses ke perangkat (malware, ekstensi berbahaya) tetap bisa membaca input.

## Ide pengembangan

- Mode passphrase (diceware) dengan daftar kata bahasa Indonesia.
- Ganti heuristik dengan zxcvbn-ts dan bandingkan hasilnya.
- Tambahkan unit test (sudah ada ekspor modul untuk Node) dan GitHub Actions.
- Daftar kata umum yang lebih besar dimuat secara lazy.
- Dukungan i18n (ID/EN).

## Referensi

- NIST SP 800-63B, Digital Identity Guidelines (Authenticators)
- OWASP ASVS, V2 Authentication
- OWASP Password Storage Cheat Sheet
- Have I Been Pwned, Pwned Passwords API (k-anonymity model)
