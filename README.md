# ModSecurity ML Integration for SQL Injection Detection

This project implements a machine learning-based SQL injection detection system integrated with ModSecurity. It uses a Random Forest classifier to detect potential SQL injection attacks and provides real-time predictions through a Flask-based API server.

## Project Structure

```
.
├── ml_model_server/
│   ├── placeholder.py        # ML server implementation
│   ├── requirements.txt      # Python dependencies
│   └── ml-server.service    # Systemd service file
├── plugin/
│   ├── machine-learning-client.lua       # ModSecurity Lua client
│   ├── machine-learning-config.conf      # ModSecurity configuration
│   └── machine-learning.load             # ModSecurity load file
├── sqli.py                  # SQL Injection detector implementation
└── README.md               # This file
```

## Features

- Real-time SQL injection detection using machine learning
- Memory-safe ModSecurity integration
- Automatic model reloading and versioning
- Rate limiting and request size validation
- Comprehensive error handling and logging
- Health check endpoints

## Requirements

### Python Dependencies
- Flask
- Flask-Limiter
- scikit-learn
- pandas
- numpy
- psutil

### System Requirements
- ModSecurity v2.9.5 or higher
- Apache2 with mod_security2
- Lua 5.1 or higher with luasocket and lua-cjson

## Installation

1. Install Python dependencies:
```bash
pip install -r ml_model_server/requirements.txt
```

2. Install Lua dependencies:
```bash
luarocks install luasocket
luarocks install lua-cjson
```

3. Configure ModSecurity:
```bash
# Copy plugin files
cp plugin/* /etc/modsecurity/

# Set permissions
chmod 755 /etc/modsecurity/lua/machine-learning-client.lua
chown www-data:www-data /etc/modsecurity/lua/machine-learning-client.lua
```

4. Setup ML server service:
```bash
cp ml_model_server/ml-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable ml-server
systemctl start ml-server
```

## Configuration

### ModSecurity Configuration
The plugin can be configured through `machine-learning-config.conf`:
- ML server URL
- Request timeouts
- Rate limits
- Memory limits

### ML Server Configuration
The ML server can be configured through environment variables:
- `ML_SERVER_PORT`: Port number (default: 5000)
- `ML_MODEL_RELOAD_INTERVAL`: Model reload interval in seconds (default: 3600)
- `ML_MAX_REQUEST_SIZE`: Maximum request size in bytes (default: 1MB)

## Usage

1. Start the ML server:
```bash
systemctl start ml-server
```

2. Enable ModSecurity rules:
```bash
a2enmod security2
systemctl restart apache2
```

3. Monitor logs:
```bash
tail -f /var/log/apache2/error.log
tail -f /var/log/ml_server.log
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP ModSecurity Core Rule Set project
- scikit-learn team
- Flask team
