# go-syslog

A high-performance syslog server written in Go with built-in log rotation and compression. Compatible with syslog-ng behavior using Unix domain sockets.

## Features

- **syslog-ng Compatible**: Uses Unix stream and datagram sockets
- **Built-in Log Rotation**: Automatic rotation when files exceed 1MB
- **Compression**: Rotated logs are automatically compressed with gzip
- **Filtering**: Supports message filtering based on log levels
- **Multiple Destinations**: Routes messages to different log files based on content
- **Thread-Safe**: Concurrent message processing with proper locking
- **Zero Dependencies**: Self-contained with no external requirements

## Installation

### From Source
```bash
git clone https://github.com/weka/go-syslog.git
cd go-syslog
go build -o go-syslog main.go
sudo cp go-syslog /usr/sbin/
sudo chmod +x /usr/sbin/go-syslog
```

### From Release
```bash
# Download latest release for your platform
wget https://github.com/weka/go-syslog/releases/download/v1.0.0/go-syslog_1.0.0_linux_amd64.tar.gz
tar -xzf go-syslog_1.0.0_linux_amd64.tar.gz
sudo cp go-syslog /usr/sbin/
sudo chmod +x /usr/sbin/go-syslog
```

## Usage

### Basic Usage
```bash
# Run the server (requires root for socket paths)
sudo go-syslog

# Check version
go-syslog --version
```

### Socket Configuration
The server listens on two Unix sockets by default:
- **Stream socket**: `/var/run/go-syslog/go-syslog.sock`
- **Datagram socket**: `/run/systemd/journal/dev-log`

### Log Destinations
Messages are routed to different files based on content:
- **All messages**: `/var/log/syslog`
- **Info/Warning/Error messages**: stdout + `/var/log/syslog`
- **Error messages only**: `/var/log/error`

## Log Rotation

### Automatic Rotation
- **Trigger**: Files rotate when they exceed 1MB
- **Naming**: `filename.YYYYMMDD-HHMMSS.gz`
- **Retention**: Keeps 10 compressed files, automatically deletes older ones
- **Compression**: All rotated files are gzip compressed

### Rotation Example
```
/var/log/
├── syslog                      # Current active log
├── syslog.20240916-143022.gz   # Compressed rotated log
├── syslog.20240916-142815.gz   # Older compressed log
└── error.20240916-143022.gz    # Compressed error log
```

## Testing

### Send Test Messages
```bash
# Send a single message
logger -u /var/run/go-syslog/go-syslog.sock "Test message"

# Send error message (will go to error log)
logger -u /var/run/go-syslog/go-syslog.sock "ERROR: Test error message"

# Fill log quickly for rotation testing
for i in {1..20}; do logger -u /var/run/go-syslog/go-syslog.sock "Test $i: $(head -c 50000 /dev/zero | tr '\0' 'A')"; done
```

### View Compressed Logs
```bash
# View compressed log
zcat /var/log/syslog.20240916-143022.gz

# Or with paging
zless /var/log/syslog.20240916-143022.gz
```

## Configuration

### Message Filtering
The server includes built-in filters:

- **Info Filter**: Matches NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY, FATAL, ASSERT
- **Error Filter**: Matches ERROR, CRITICAL, ALERT, EMERGENCY, FATAL, ASSERT

### Message Format
Output format: `$ISODATE $MSGHDR | $MSG`

Example:
```
2024-09-16T15:30:22+03:00 hostname program[1234]: | Test message
```

## Systemd Service

Create a systemd service file:

```bash
sudo tee /etc/systemd/system/go-syslog.service << EOF
[Unit]
Description=Go Syslog Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/go-syslog
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable go-syslog
sudo systemctl start go-syslog
```

## Monitoring

### Check Status
```bash
# Service status
sudo systemctl status go-syslog

# View logs
sudo journalctl -u go-syslog -f

# Check socket files
ls -la /var/run/go-syslog/
ls -la /run/systemd/journal/dev-log
```

### Log File Sizes
```bash
# Monitor log sizes
watch -n 1 'ls -lah /var/log/syslog* /var/log/error* 2>/dev/null'
```

## Architecture

### Components
- **Unix Socket Listeners**: Handle stream and datagram connections
- **Message Parser**: Parses RFC3164 syslog messages
- **Filter Engine**: Routes messages based on content patterns
- **Rotation Manager**: Handles file rotation, compression, and cleanup
- **Destination Manager**: Manages multiple log file destinations

### Thread Safety
- Per-destination mutexes for safe concurrent writes
- Atomic file rotation operations
- Background compression to avoid blocking writes

## Troubleshooting

### Permission Issues
```bash
# Ensure correct permissions
sudo chown root:root /usr/sbin/go-syslog
sudo chmod 755 /usr/sbin/go-syslog

# Create socket directories
sudo mkdir -p /var/run/go-syslog
sudo mkdir -p /run/systemd/journal
```

### Socket Issues
```bash
# Check if sockets are created
sudo lsof -U | grep go-syslog

# Remove stale sockets
sudo rm -f /var/run/go-syslog/go-syslog.sock
sudo rm -f /run/systemd/journal/dev-log
```

### Log Issues
```bash
# Check log directory permissions
sudo ls -la /var/log/

# Manually create log directory
sudo mkdir -p /var/log
sudo chown root:root /var/log
```

## Development

### Build
```bash
go build -o go-syslog main.go
```

### Test
```bash
# Run locally (will need sudo for socket paths)
sudo ./go-syslog

# Test with custom paths (modify code as needed)
# Change socket paths for testing without root
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Changelog

### v1.0.0
- Initial release with syslog-ng compatibility
- Built-in log rotation and compression
- Unix socket support
- Message filtering and routing