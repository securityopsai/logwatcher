# LogWatcher

Testing utility for log monitoring and regex pattern detection. Build for testing detection engineering stuff.

⚠️ This is a testing tool - use at your own responsibility.

## Main Purpose
- Test regex patterns against log files
- Experiment with different detection approaches
- Validate pattern matching in real-time
- Test notification workflows

## Key Features
- Real-time log monitoring
- Regex pattern matching
- Multiple notification channels (email, Slack, Teams, Telegram)
- Windows and Linux support
- Context capture around matches

## Quick Start

1. Install:
```bash
pip install -r requirements.txt
```

2. Edit config.json with your patterns:
```json
{
    "patterns": {
        "error": "(?i)\\b(error|exception|fail)\\b",
        "warning": "(?i)\\b(warning|alert)\\b"
    },
    "file_patterns": {
        "your_log.log": ["error", "warning"]
    }
}
```

3. Run in test mode:
```bash
python log_prod.py config.json --test
```

## Testing Tips
- Start with test mode (--test flag)
- Test patterns in small log files first
- Use the example config as a template
- Check context buffer settings for your needs

## Note
This is a testing tool to validate detection approaches. Not intended for production monitoring.