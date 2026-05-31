# Instruksi Menjalankan Tests

Jalankan semua perintah dari root repository.

## 1. Install dependensi

```bash
python -m pip install -r requirements.txt
```

## 2. Jalankan seluruh test

```bash
python -m pytest
```

## 3. Jalankan test crypto saja

```bash
python -m pytest tests/test_crypto.py
```

Jika berhasil, pytest akan menampilkan semua test dengan status `passed`.
