from typing import Dict, Any
import jsonschema

CONFIG_SCHEMA = {
    "type": "object",
    "required": ["patterns", "file_patterns", "settings", "notifications", "notification_rules"],
    "properties": {
        "patterns": {
            "type": "object",
            "additionalProperties": {"type": "string"}
        },
        "file_patterns": {
            "type": "object",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"}
            }
        },
        "settings": {
            "type": "object",
            "required": ["encoding", "read_chunk_size", "notification_rate_limit"],
            "properties": {
                "encoding": {"type": "string"},
                "read_chunk_size": {"type": "integer", "minimum": 1024},
                "notification_rate_limit": {"type": "integer", "minimum": 0},
                "max_file_size": {"type": "integer", "minimum": 0},
                "buffer_size": {"type": "integer", "minimum": 1},
                "max_retries": {"type": "integer", "minimum": 1}
            }
        },
        "notifications": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "smtp_server": {"type": "string"},
                        "smtp_port": {"type": "integer"},
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                        "to_address": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["enabled"]
                },
                "slack": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "webhook_url": {"type": "string"}
                    },
                    "required": ["enabled"]
                },
                "teams": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "webhook_url": {"type": "string"}
                    },
                    "required": ["enabled"]
                },
                "telegram": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "bot_token": {"type": "string"},
                        "chat_id": {"type": "string"}
                    },
                    "required": ["enabled"]
                },
                "syslog": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "facility": {"type": "string"},
                        "protocol": {"type": "string"},
                        "tag": {"type": "string"}
                    },
                    "required": ["enabled"]
                }
            }
        },
        "notification_rules": {
            "type": "object",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"}
            }
        }
    }
}

def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate the configuration against the schema.
    
    Args:
        config: Configuration dictionary to validate
        
    Raises:
        jsonschema.exceptions.ValidationError: If configuration is invalid
    """
    jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)

# Default configuration template
DEFAULT_CONFIG = {
    "settings": {
        "encoding": "utf-8",
        "read_chunk_size": 4096,
        "notification_rate_limit": 60,
        "max_file_size": 100_000_000,  # 100MB
        "buffer_size": 20,
        "max_retries": 3
    },
    "patterns": {},
    "file_patterns": {},
    "notifications": {
        "email": {"enabled": False},
        "slack": {"enabled": False},
        "teams": {"enabled": False},
        "telegram": {"enabled": False},
        "syslog": {"enabled": False}
    },
    "notification_rules": {}
}