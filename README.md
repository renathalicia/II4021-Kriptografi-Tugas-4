# II4021 Kriptografi Tugas 4 - Implementasi Shamir Secret Sharing pada Aplikasi Password Manager Terdistribusi


Pengelola kata sandi berbasis CLI dengan arsitektur client-server. Isi vault
dienkripsi memakai AES-128-GCM, dan master key untuk membukanya dipecah menjadi
tiga share dengan Shamir Secret Sharing skema (2,3). Vault hanya terbuka bila
minimal dua share digabungkan, sehingga tidak ada satu pihak pun termasuk
server yang bisa membuka vault sendirian.

Dua mode akses:
- Mode normal: kombinasi local share + server share. Bisa lihat, tambah, ubah, hapus.
- Mode backup: kombinasi local share + recovery share. Read-only, dipakai saat server mati.

## Teknologi yang digunakan

- Python 3
- Flask — server HTTP
- SQLite — penyimpanan data terenkripsi di server
- cryptography — AES-128-GCM dan PBKDF2 (KDF)
- pycryptodome — Shamir Secret Sharing
- qrcode + Pillow — QR code dan kriptografi visual recovery share (bonus)
- requests — komunikasi HTTP sisi klien
- pytest — pengujian

## Dependensi

Tercantum di `requirements.txt`: cryptography, pycryptodome, qrcode, Pillow,
pytest, flask, requests.

## Cara menjalankan

Jalankan semua perintah dari root repository.

1. (Opsional) buat virtual environment:

       python -m venv .venv
       source .venv/bin/activate        # Windows: .venv\Scripts\activate

2. Install dependensi:

       python -m pip install -r requirements.txt

3. Jalankan server (terminal pertama):

       python -m server.app

   Server berjalan di http://127.0.0.1:5000

4. Jalankan klien (terminal kedua):

       python -m client.main

   Ikuti menu: setup vault baru, buka mode normal, atau buka mode backup.

5. (Opsional) jalankan pengujian:

       python -m pytest

## Environment / konfigurasi

Konfigurasi server di `server/config.py`:
- HOST: 127.0.0.1
- PORT: 5000
- DATABASE_PATH: data/server.db (dibuat otomatis saat pertama kali run)
- DEBUG: False

Konfigurasi klien:
- BASE_URL server di `client/services/api_client.py` (default http://127.0.0.1:5000)
- Data lokal klien di folder `data/`:
  - client_config.json — local share terenkripsi, salt KDF, parameter KDF
  - backup_vault.json — backup vault terenkripsi untuk mode backup

Folder `data/` diabaikan git (lihat `.gitignore`) karena berisi data pengguna lokal.

## Struktur direktori

    client/   kode klien: CLI, services, crypto, storage, models
    server/   kode server: Flask app, routes, models, database, schema
    tests/    pengujian crypto, server, dan end-to-end
    docs/     dokumentasi dan screenshot

## Anggota kelompok

- Samuel Chris Michael Bagasta S (18223011)
- Carlen Asadel Axelle (18223017)
- Audy Alicia Renatha Tirayoh (18223097)