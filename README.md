# Attack Surface Management (ASM)

Sistem otomatis untuk enumerasi dan monitoring attack surface dengan mengidentifikasi subdomain, menyelesaikan DNS, melakukan HTTP probing, dan memberikan risk hints sederhana.

## 🎯 Tujuan

- **Input**: Domain utama
- **Proses**:
  - Enumerasi subdomain (crt.sh + brute force opsional)
  - Resolusi DNS
  - HTTP/HTTPS probing
  - Analisis sederhana untuk deteksi anomali
- **Output**: JSON atau CSV dengan informasi lengkap dan risk hints
- **Scope**: Visibility dan inventory, bukan vulnerability scanning/exploitation

## 📋 Fitur

- ✅ Enumerasi subdomain pasif (crt.sh)
- ✅ Brute force DNS subdomain (opsional)
- ✅ Resolusi DNS massal dengan concurrency control
- ✅ HTTP/HTTPS probing untuk setiap host
- ✅ Deteksi risiko sederhana:
  - `no-https` - Host hanya accessible via HTTP
  - `open-redirect-chain` - Kemungkinan open redirect
  - `tls-expiring-soon` - Sertifikat TLS akan kadaluarsa
  - `suspicious-title` - Judul halaman mencurigakan
  - `exposed-admin` - Heuristic untuk exposed admin panels
- ✅ Output format: JSON atau CSV
- ✅ Concurrent requests dengan batching control

## 📦 Instalasi

### Requirements

- Python 3.10+
- pip

### Setup

```bash
# Clone repository
git clone https://github.com/isanimal/AttackSurfaceManagement.git
cd AttackSurfaceManagement

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Penggunaan

### Basic Usage

```bash
# Output JSON (default)
python asm_v0/main.py -d example.com -o results.json

# Output CSV
python asm_v0/main.py -d example.com -o results.csv
```

### Advanced Options

```bash
# Dengan control concurrency dan timeout
python asm_v0/main.py -d example.com -o out.json --concurrency 100 --timeout 10

# Dengan wordlist brute force
python asm_v0/main.py -d example.com -o out.json --wordlist wordlist.txt --concurrency 50

# Passive only (tanpa brute force)
python asm_v0/main.py -d example.com -o out.json --passive-only

# Dengan limit subdomain
python asm_v0/main.py -d example.com -o out.json --max-subdomains 500
```

### Parameter

| Parameter          | Deskripsi                                     | Default  |
| ------------------ | --------------------------------------------- | -------- |
| `-d, --domain`     | Domain target                                 | Required |
| `-o, --output`     | File output (format ditentukan dari ekstensi) | Required |
| `--wordlist`       | Path ke wordlist untuk brute force            | Optional |
| `--passive-only`   | Hanya passive enumeration                     | False    |
| `--concurrency`    | Jumlah concurrent requests                    | 50       |
| `--timeout`        | Timeout per request (detik)                   | 10       |
| `--max-subdomains` | Limit jumlah subdomain                        | 10000    |

## 📁 Struktur Project

```
asm_v0/
├── main.py              # Entry point
├── enumerator.py        # Subdomain enumeration (crt.sh + brute)
├── resolver.py          # DNS resolution
├── probe.py             # HTTP/HTTPS probing
├── fingerprint.py       # Service fingerprinting
├── rules.py             # Risk detection rules
├── output.py            # Output formatting (JSON/CSV)
├── utils.py             # Utility functions
└── README.md            # Dokumentasi v0
```

## 🔍 Output Format

### JSON Output

```json
{
  "domain": "example.com",
  "timestamp": "2024-01-14T10:30:00Z",
  "results": [
    {
      "host": "www.example.com",
      "ips": ["93.184.216.34"],
      "status_code": 200,
      "https": true,
      "title": "Example Domain",
      "risks": [],
      "tls_expiry": "2025-06-15"
    },
    {
      "host": "admin.example.com",
      "ips": ["93.184.216.34"],
      "status_code": 401,
      "https": true,
      "title": "Admin Panel",
      "risks": ["exposed-admin"],
      "tls_expiry": "2025-06-15"
    }
  ],
  "summary": {
    "total_hosts": 2,
    "https_enabled": 2,
    "with_risks": 1
  }
}
```

### CSV Output

```csv
host,ips,status_code,https,title,risks,tls_expiry
www.example.com,93.184.216.34,200,True,Example Domain,,2025-06-15
admin.example.com,93.184.216.34,401,True,Admin Panel,exposed-admin,2025-06-15
```

## ⚙️ Catatan Teknis

- **crt.sh Rate Limiting**: crt.sh kadang tidak stabil atau rate-limited. Tool tetap menghasilkan minimal record untuk domain utama.
- **DNS CNAME**: v0 belum mengambil record CNAME untuk menjaga dependency minimal.
- **Concurrency**: Gunakan `--concurrency 50-100` untuk balanced performance. Terlalu tinggi bisa trigger rate-limiting.
- **Timeout**: Untuk network lambat, increase `--timeout` ke 15-20 detik.
- **Wordlist**: Gunakan wordlist berkualitas untuk hasil brute force yang lebih baik.

## 🛠️ Troubleshooting

### ImportError: cannot import name 'bounded_gather'

Pastikan semua dependencies ter-install dan `utils.py` memiliki function `bounded_gather`.

### crt.sh returns empty results

Normal terjadi kadang. Tool tetap akan enumerate domain utama dan melakukan brute force jika tersedia wordlist.

### Too many timeouts

- Reduce `--concurrency`
- Increase `--timeout`
- Check network connectivity

## 📝 Requirements

```
aiohttp>=3.9,<4.0
```

## 📄 Lisensi

[Lisensi sesuai kebutuhan]

## 👤 Author

isanimal - [GitHub](https://github.com/isanimal)

## 🤝 Kontribusi

Issues dan pull requests welcome!
