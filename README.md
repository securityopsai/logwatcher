# LogWatcher

An advanced, production-ready log monitoring tool with real-time pattern matching and multi-channel notifications. Built with performance and reliability in mind, it supports both Windows and Linux environments.

## Features

### Core Functionality
- 🔍 Real-time log file monitoring with pattern matching
- 📊 Circular buffer for context preservation around matches
- 🔄 Automatic log rotation detection and handling
- ⚡ Asynchronous notification processing
- 🎯 Rate limiting to prevent alert fatigue

### Cross-Platform Support
- 🪟 Windows support using native Win32 APIs
- 🐧 Linux support using inotify
- 💻 Platform-specific optimizations

### Advanced Monitoring
- 🎯 Regex-based pattern matching
- 📝 Context preservation around matches
- 📊 File size and permission checks
- 🔄 Automatic file rotation handling
- ⚡ Efficient read chunking

### Notifications
- 📧 Email notifications
- 💬 Slack integration
- 📱 Microsoft Teams support
- 📲 Telegram notifications
- 📝 Syslog forwarding

### Reliability Features
- 🔄 Automatic reconnection handling
- 💪 Robust error handling
- 🛡️ Resource cleanup on shutdown
- 📊 Health monitoring
- 📈 Performance metrics

### Monitoring & Metrics
- 📊 Comprehensive metrics collection
- 🔍 Pattern match statistics
- ⚠️ Error tracking
- 📈 Performance monitoring
- 🔄 Real-time health checks

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/securityopsai/logwatcher.git
cd logwatcher
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Basic Usage

1. Create a configuration file (or modify the provided example):
```json
{
    "settings": {
        "encoding": "utf-8",
        "read_chunk_size": 4096,
        "notification_rate_limit": 60
    },
    "patterns": {
        "error": "(?i)\\b(error|exception|fail|critical)\\b",
        "warning": "(?i)\\b(warning|warn|alert)\\b"
    },
    "file_patterns": {
        "/path/to/your/app.log": ["error", "warning"]
    }
}
```

2. Run LogWatcher:
```bash
python log_prod.py config.json
```

### Test Mode

Run without sending actual notifications:
```bash
python log_prod.py config.json --test
```

## Configuration

### Full Configuration Example
```json
{
    "settings": {
        "encoding": "utf-8",
        "read_chunk_size": 4096,
        "notification_rate_limit": 60,
        "max_file_size": 100000000,
        "buffer_size": 20,
        "max_retries": 3
    },
    "patterns": {
        "error": "(?i)\\b(error|exception|fail|critical)\\b",
        "warning": "(?i)\\b(warning|warn|alert)\\b",
        "security": "(?i)\\b(unauthorized|forbidden|invalid\\stoken)\\b"
    },
    "file_patterns": {
        "/var/log/app.log": ["error", "warning"],
        "/var/log/auth.log": ["security"]
    },
    "notifications": {
        "email": {
            "enabled": true,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "username": "alerts@example.com",
            "password": "your_password",
            "to_address": ["team@example.com"]
        },
        "slack": {
            "enabled": true,
            "webhook_url": "https://hooks.slack.com/services/..."
        }
    },
    "notification_rules": {
        "error": ["email", "slack"],
        "security": ["email", "slack", "telegram"]
    }
}
```

### Component Configuration

#### Patterns
Define regex patterns to match in your logs:
```json
"patterns": {
    "pattern_name": "regex_pattern"
}
```

#### File Patterns
Map log files to patterns:
```json
"file_patterns": {
    "/path/to/log": ["pattern1", "pattern2"]
}
```

#### Notification Rules
Define which notifications to send for each pattern:
```json
"notification_rules": {
    "pattern_name": ["email", "slack"]
}
```

## Architecture

### Components

- **LogWatcher**: Core monitoring engine
- **BufferManager**: Manages circular buffers for context
- **NotificationManager**: Handles multi-channel notifications
- **HealthMonitor**: Monitors system health
- **MetricsCollector**: Collects performance metrics
- **RateLimiter**: Prevents notification flooding

### Performance Considerations

- Efficient file reading with chunking
- Asynchronous notification processing
- Rate limiting for notifications
- Resource cleanup and management
- Cross-platform optimizations

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Adding New Features

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Production Usage

### System Requirements

- Python 3.7+
- For Windows: pywin32
- For Linux: inotify
- Memory: 256MB minimum
- CPU: Single core minimum

### Best Practices

1. Monitor log file sizes
2. Set appropriate rate limits
3. Use pattern testing mode first
4. Configure health monitoring
5. Regular configuration review

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors!
- Inspired by the need for robust log monitoring in production environments
- Built with ❤️ by SecurityOpsAI team
