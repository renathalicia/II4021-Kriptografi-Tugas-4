# II4021-Kriptografi-Tugas-4

## Dependensi

- `cryptography` untuk AES-GCM dan PBKDF2.
- `pycryptodome` untuk Shamir Secret Sharing.
- `qrcode` untuk membuat QR recovery share.
- `Pillow` untuk pemrosesan gambar visual cryptography.
- `pytest` untuk menjalankan pengujian.

Format share aplikasi tetap berupa JSON `{"x": int, "y": "base64"}` agar mudah disimpan di client, dikirim ke server, dan dimasukkan ke QR code.
