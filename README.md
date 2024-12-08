# ModSecurity Machine Learning Plugin Integration

Integrasi ModSecurity dengan Machine Learning untuk deteksi serangan yang lebih akurat.

## Komponen Utama

### 1. ModSecurity Plugin
- Konfigurasi ML plugin dengan rule ID range 9516100-9516130
- Lua script untuk komunikasi dengan ML server
- Integrasi dengan OWASP Core Rule Set (CRS)

### 2. ML Server
- Flask server yang menjalankan model machine learning
- Endpoint prediksi di port 5000
- Systemd service untuk manajemen otomatis
- Model untuk deteksi SQL Injection dan serangan web lainnya

## Struktur File

```
.
├── plugin/
│   ├── machine-learning.conf     # Konfigurasi ModSecurity ML plugin
│   └── machine-learning-client.lua # Lua script untuk ML
├── ml_model_server/
│   ├── placeholder.py           # ML server implementation
│   └── sql_injection_detector.pkl # Pre-trained ML model
└── config/
    ├── modsecurity/            # Konfigurasi ModSecurity
    └── apache2/               # Konfigurasi Apache
```

## Instalasi

### Prerequisites
- Apache2
- ModSecurity
- OWASP CRS
- Python 3.8+
- Flask dan dependensi Python lainnya

### Langkah Instalasi

1. Setup ModSecurity:
```bash
# Copy file konfigurasi
sudo cp plugin/machine-learning.conf /etc/modsecurity/plugin/machine-learning/
sudo cp plugin/machine-learning-client.lua /etc/modsecurity/plugin/machine-learning/
```

2. Setup ML Server:
```bash
# Copy ML server files
sudo mkdir -p /var/www/onlineshoplrv/ml_model_server
sudo cp ml_model_server/* /var/www/onlineshoplrv/ml_model_server/

# Setup service
sudo cp config/ml-server.service /etc/systemd/system/
sudo systemctl enable ml-server
sudo systemctl start ml-server
```

## Penggunaan

### Testing Basic
```bash
# Test normal request (should pass)
curl "http://localhost/test/search?q=hello"

# Test SQL injection (should be blocked)
curl "http://localhost/test/search?q=1' OR '1'='1"
```

### Monitoring

1. ModSecurity Logs:
```bash
sudo tail -f /var/log/apache2/error.log
sudo tail -f /var/log/apache2/modsec_debug.log
```

2. ML Server Logs:
```bash
sudo journalctl -u ml-server -f
```

## Troubleshooting

### Common Issues

1. ML Server tidak berjalan:
```bash
sudo systemctl status ml-server
sudo journalctl -u ml-server -n 50
```

2. ModSecurity blocking legitimate traffic:
- Check `/var/log/apache2/error.log`
- Adjust anomaly score threshold in `machine-learning.conf`

## Maintenance

- Regular model updates
- Log rotation
- Performance monitoring
- Rule tuning based on false positives/negatives

## Security Considerations

- ML Server hanya bisa diakses dari localhost
- Secure communication antara ModSecurity dan ML Server
- Regular updates untuk semua komponen
- Monitoring false positives/negatives

## License

This project is licensed under the Apache License 2.0

## Authors

- Original CRS ML Plugin Team
- Custom modifications by Security Team
