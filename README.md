# b07 — API Produksi Mini: Kasir

API kasir lengkap: auth (register/login + token HMAC), CRUD produk dengan
database SQLite persisten, validasi input, pagination, dan error format konsisten.

## Cara menjalankan (lokal)
```bash
cd exercises/backend/b07
python3 server.py 8007        # DB kasir.db dibuat otomatis + seed 6 produk
# Auth secret produksi: AUTH_SECRET="<acak>" python3 server.py 8007
```

## Endpoint
| Method | URL | Auth | Keterangan |
|---|---|---|---|
| POST | /api/register | — | body: nama, email, password (min 8) -> 201 |
| POST | /api/login | — | body: email, password -> 200 + token (exp 1 jam) |
| GET | /api/profil | Bearer | -> 200 data user |
| GET | /api/produk?page=1&limit=10 | Bearer | pagination, meta {page, limit, total} |
| GET | /api/produk/{id} | Bearer | 404 bila tidak ada |
| POST | /api/produk | Bearer | body: nama, harga>0, stok>=0 -> 201 |
| PUT | /api/produk/{id} | Bearer | update parsial -> 200 |
| DELETE | /api/produk/{id} | Bearer | -> 204 |

## Keamanan
- Password: PBKDF2-HMAC-SHA256 (200.000 iterasi, salt acak) — bcrypt tidak
  tersedia di VM ini, PBKDF2 adalah hashing aman stdlib (dicatat di b04).
- Token: HMAC-SHA256 + expiry 1 jam; semua query SQL parameter binding.
- Batas body 100 KB (413), validasi tipe di pintu masuk, tanpa stack trace.
- Yang belum ada (dicatat jujur): rate limiting, HTTPS, refresh token.

## Deploy
STATUS: **BELUM DEPLOY**. Deploy ke server gratis (Railway/Render/Fly.io/dll)
butuh akun cloud + login browser, yang tidak tersedia dari VM ini.
Server diuji lokal (lihat `test-curl.txt`); langkah deploy saat akun tersedia:
1. Push repo ke GitHub, 2. buat service di Railway/Render dari repo,
3. set env `AUTH_SECRET`, 4. tes endpoint publik dari HP.
