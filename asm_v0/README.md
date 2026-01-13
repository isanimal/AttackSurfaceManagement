ASM v0 (minimal Attack Surface Inventory)

Tujuan:
- Input domain -> enumerasi subdomain (crt.sh + brute opsional) -> DNS resolve -> HTTP/HTTPS probe -> output JSON/CSV
- Tidak melakukan vulnerability scanning / exploitation. Hanya visibility + risk hints sederhana.

Install:
- Python 3.10+
- pip install aiohttp

Run:
- JSON:
  python main.py -d example.com -o out.json --concurrency 100 --timeout 10

- CSV:
  python main.py -d example.com -o out.csv --concurrency 100 --timeout 10

Wordlist brute (opsional):
  python main.py -d example.com -o out.json --wordlist wordlist.txt

Passive only:
  python main.py -d example.com -o out.json --passive-only

Risk hints (v0):
- no-https
- open-redirect-chain
- tls-expiring-soon
- suspicious-title
- exposed-admin (heuristic based)

Catatan:
- crt.sh kadang rate-limit / tidak stabil. Jika kosong, tetap menghasilkan record minimal untuk domain.
- DNS CNAME tidak diambil pada v0 (dependency minimal).
