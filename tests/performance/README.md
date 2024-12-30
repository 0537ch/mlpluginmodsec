# ModSecurity Performance Testing Suite

Script ini digunakan untuk membandingkan performa antara ModSecurity traditional rules dan machine learning based detection.

## Struktur
```
tests/performance/
├── run_benchmark.py     # Script utama untuk benchmark
├── test_cases.json      # Test cases untuk rules dan ML
├── requirements.txt     # Dependencies
└── README.md           # Dokumentasi
```

## Fitur
- Pengujian concurrent requests
- Pengukuran response time
- Perhitungan detection rate
- Analisis false positives
- Pengujian edge cases
- Laporan detail dalam format JSON

## Metrics yang Diukur
1. Response Time
   - Average
   - Median
   - Min/Max
2. Detection Rate
3. False Positive Rate
4. Resource Usage

## Cara Penggunaan

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Sesuaikan test_cases.json sesuai kebutuhan

3. Jalankan benchmark:
```bash
python3 run_benchmark.py
```

4. Hasil akan disimpan dalam file JSON dengan format:
```
benchmark_report_YYYYMMDD_HHMMSS.json
```

## Test Cases
- Rules Test Cases: Pengujian traditional ModSecurity rules
- ML Test Cases: Pengujian machine learning detection

## Notes
- Pastikan ModSecurity dan ML server sudah running
- Sesuaikan base_url di script jika berbeda
- Tambahkan test cases baru di test_cases.json
