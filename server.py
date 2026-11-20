"""b07 — API Produksi Mini: kasir (auth + CRUD + validasi + pagination + SQLite).
Gabungan b02+b03+b04+b05. Semua query SQL memakai parameter binding (?).
Jalankan: python3 server.py [port] [db-path]  (default 8007, ./kasir.db)
Endpoint:
  POST /api/register, POST /api/login, GET /api/profil (Bearer)
  GET  /api/produk?page=&limit=   POST /api/produk
  GET  /api/produk/{id}  PUT /api/produk/{id}  DELETE /api/produk/{id}
  (semua /api/produk butuh Bearer token)
"""
import base64, hashlib, hmac, json, os, re, secrets, sqlite3, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("AUTH_SECRET", "dev-secret-jangan-dipakai-produksi").encode()
DB = os.environ.get("DB_PATH", "kasir.db")

class BodyTooLarge(Exception):
    pass

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL, hash TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS produk (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT NOT NULL, harga INTEGER NOT NULL CHECK (harga > 0),
            stok INTEGER NOT NULL DEFAULT 0 CHECK (stok >= 0),
            dibuat_pada TEXT NOT NULL DEFAULT (datetime('now')))""")
        if c.execute("SELECT COUNT(*) FROM produk").fetchone()[0] == 0:
            c.executemany("INSERT INTO produk (nama, harga, stok) VALUES (?,?,?)",
                          [("Kopi", 18000, 50), ("Susu", 22000, 30),
                           ("Gula", 15000, 100), ("Teh", 12000, 40),
                           ("Roti", 10000, 25), ("Mie Instan", 3500, 200)])

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()

def buat_token(email, ttl=3600):
    p = b64e(json.dumps({"sub": email, "exp": int(time.time()) + ttl}).encode())
    return p + "." + b64e(hmac.new(SECRET, p.encode(), hashlib.sha256).digest())

def cek_token(tok):
    try:
        p, sig = tok.split(".")
        if not hmac.compare_digest(sig, b64e(hmac.new(SECRET, p.encode(), hashlib.sha256).digest())):
            return None
        payload = json.loads(b64d(p))
        return payload["sub"] if payload["exp"] >= time.time() else None
    except Exception:
        return None

def kirim(h, status, obj):
    body = json.dumps(obj).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)

def baca_body(h, limit=100_000):
    n = int(h.headers.get("Content-Length") or 0)
    if n > limit:
        raise BodyTooLarge()
    raw = h.rfile.read(n) if n else b"{}"
    return json.loads(raw.decode() or "{}")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def valid_produk(b):
    if not isinstance(b.get("nama"), str) or len(b["nama"].strip()) < 2:
        return "nama minimal 2 karakter"
    if not isinstance(b.get("harga"), (int, float)) or isinstance(b.get("harga"), bool) or b["harga"] <= 0:
        return "harga harus angka > 0"
    if "stok" in b and (not isinstance(b["stok"], int) or isinstance(b["stok"], bool) or b["stok"] < 0):
        return "stok harus bilangan bulat >= 0"
    return None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth(self):
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return None
        return cek_token(auth[7:])

    def _body(self):
        try:
            b = baca_body(self)
        except BodyTooLarge:
            kirim(self, 413, {"error": "body terlalu besar"})
            return None
        except Exception:
            kirim(self, 400, {"error": "body JSON tidak valid"})
            return None
        if not isinstance(b, dict):
            kirim(self, 400, {"error": "body harus objek JSON"})
            return None
        return b

    def do_POST(self):
        path = self.path.split("?")[0]
        b = self._body()
        if b is None:
            return
        if path == "/api/register":
            nama, email, pw = b.get("nama"), b.get("email"), b.get("password")
            if not isinstance(nama, str) or len(nama.strip()) < 2:
                return kirim(self, 400, {"error": "nama minimal 2 karakter"})
            if not isinstance(email, str) or not EMAIL_RE.match(email):
                return kirim(self, 400, {"error": "email tidak valid"})
            if not isinstance(pw, str) or len(pw) < 8:
                return kirim(self, 400, {"error": "password minimal 8 karakter"})
            salt = secrets.token_bytes(16)
            try:
                with db() as c:
                    c.execute("INSERT INTO users (nama, email, salt, hash) VALUES (?,?,?,?)",
                              (nama.strip(), email, salt.hex(), hash_pw(pw, salt)))
            except sqlite3.IntegrityError:
                return kirim(self, 409, {"error": "email sudah terdaftar"})
            return kirim(self, 201, {"data": {"nama": nama.strip(), "email": email}})
        if path == "/api/login":
            email, pw = b.get("email"), b.get("password")
            with db() as c:
                row = c.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone() if isinstance(email, str) else None
            if not row or not isinstance(pw, str) or not hmac.compare_digest(row["hash"], hash_pw(pw, bytes.fromhex(row["salt"]))):
                return kirim(self, 401, {"error": "email atau password salah"})
            return kirim(self, 200, {"data": {"token": buat_token(email)}})
        if path == "/api/produk":
            email = self._auth()
            if not email:
                return kirim(self, 401, {"error": "token tidak valid atau kedaluwarsa"})
            err = valid_produk(b)
            if err:
                return kirim(self, 400, {"error": err})
            with db() as c:
                cur = c.execute("INSERT INTO produk (nama, harga, stok) VALUES (?,?,?)",
                                (b["nama"].strip(), b["harga"], b.get("stok", 0)))
                pid = cur.lastrowid
                row = c.execute("SELECT * FROM produk WHERE id = ?", (pid,)).fetchone()
            return kirim(self, 201, {"data": dict(row)})
        return kirim(self, 404, {"error": "route tidak ditemukan"})

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        if u.path == "/api/profil":
            email = self._auth()
            if not email:
                return kirim(self, 401, {"error": "token tidak valid atau kedaluwarsa"})
            with db() as c:
                row = c.execute("SELECT nama, email FROM users WHERE email = ?", (email,)).fetchone()
            return kirim(self, 200, {"data": dict(row)}) if row else kirim(self, 401, {"error": "user tidak ditemukan"})
        if u.path == "/api/produk" or u.path.startswith("/api/produk/"):
            email = self._auth()
            if not email:
                return kirim(self, 401, {"error": "token tidak valid atau kedaluwarsa"})
            if u.path == "/api/produk":
                q = parse_qs(u.query)
                try:
                    page = max(1, int(q.get("page", ["1"])[0]))
                    limit = min(100, max(1, int(q.get("limit", ["10"])[0])))
                except ValueError:
                    return kirim(self, 400, {"error": "page/limit harus angka"})
                with db() as c:
                    total = c.execute("SELECT COUNT(*) FROM produk").fetchone()[0]
                    rows = c.execute("SELECT * FROM produk ORDER BY id LIMIT ? OFFSET ?",
                                     (limit, (page - 1) * limit)).fetchall()
                return kirim(self, 200, {"data": [dict(r) for r in rows],
                                          "meta": {"page": page, "limit": limit, "total": total}})
            pid = u.path.rsplit("/", 1)[-1]
            if not pid.isdigit():
                return kirim(self, 404, {"error": "route tidak ditemukan"})
            with db() as c:
                row = c.execute("SELECT * FROM produk WHERE id = ?", (int(pid),)).fetchone()
            return kirim(self, 200, {"data": dict(row)}) if row else kirim(self, 404, {"error": "produk tidak ditemukan"})
        return kirim(self, 404, {"error": "route tidak ditemukan"})

    def do_PUT(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "produk"] and parts[2].isdigit():
            email = self._auth()
            if not email:
                return kirim(self, 401, {"error": "token tidak valid atau kedaluwarsa"})
            b = self._body()
            if b is None:
                return
            pid = int(parts[2])
            with db() as c:
                row = c.execute("SELECT * FROM produk WHERE id = ?", (pid,)).fetchone()
                if not row:
                    return kirim(self, 404, {"error": "produk tidak ditemukan"})
                merged = dict(row); merged.update(b)
                err = valid_produk(merged)
                if err:
                    return kirim(self, 400, {"error": err})
                c.execute("UPDATE produk SET nama=?, harga=?, stok=? WHERE id=?",
                          (merged["nama"], merged["harga"], merged.get("stok", 0), pid))
                row = c.execute("SELECT * FROM produk WHERE id = ?", (pid,)).fetchone()
            return kirim(self, 200, {"data": dict(row)})
        return kirim(self, 404, {"error": "route tidak ditemukan"})

    def do_DELETE(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "produk"] and parts[2].isdigit():
            email = self._auth()
            if not email:
                return kirim(self, 401, {"error": "token tidak valid atau kedaluwarsa"})
            pid = int(parts[2])
            with db() as c:
                cur = c.execute("DELETE FROM produk WHERE id = ?", (pid,))
                if cur.rowcount == 0:
                    return kirim(self, 404, {"error": "produk tidak ditemukan"})
            self.send_response(204); self.end_headers()
            return
        return kirim(self, 404, {"error": "route tidak ditemukan"})

if __name__ == "__main__":
    import sys
    init_db()
    # Deploy: port dari argv (lokal) atau env PORT (Render/Railway); bind 0.0.0.0
    # agar bisa dijangkau dari luar container. Lokal tetap 127.0.0.1:8007 default.
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8007))
    print(f"b07 kasir API jalan di http://0.0.0.0:{port} (DB: {DB})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
