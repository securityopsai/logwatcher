import smtplib
import requests
import logging
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Callable, Any
from functools import wraps

def retry_on_exception(max_retries: int = 3, delay: float = 1.0):
    """Decorator for retrying operations that might fail temporarily."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))  # Exponential backoff
                    continue
            raise last_exception
        return wrapper
    return decorator

class NotificationManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("NotificationManager")
        self.notifiers = {
            'email': self.send_email,
            'slack': self.send_slack,
            'teams': self.send_teams,
            'telegram': self.send_telegram
        }

    def notify(self, pattern_name: str, message: str) -> None:
        """
        Send notifications based on pattern matches.
        
        Args:
            pattern_name: Name of the matched pattern
            message: Message to send
        """
        if pattern_name not in self.config.get('notification_rules', {}):
            self.logger.debug(f"No notification rules for pattern: {pattern_name}")
            return

        for method in self.config['notification_rules'][pattern_name]:
            if (method in self.config['notifications'] and 
                self.config['notifications'][method].get('enabled', False)):
                try:
                    self.notifiers[method](message)
                    self.logger.debug(f"Successfully sent {method} notification for {pattern_name}")
                except Exception as e:
                    self.logger.error(f"Failed to send {method} notification: {str(e)}")

    @retry_on_exception()
    def send_email(self, message: str) -> None:
        """Send email notification with retry logic."""
        email_config = self.config['notifications']['email']
        msg = MIMEMultipart()
        msg['From'] = email_config['username']
        msg['To'] = ', '.join(email_config['to_address'])
        msg['Subject'] = f"LogWatcher Alert"
        msg.attach(MIMEText(message, 'plain'))

        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)

    @retry_on_exception()
    def send_slack(self, message: str) -> None:
        """Send Slack notification with retry logic."""
        slack_config = self.config['notifications']['slack']
        payload = {
            'text': message,
            'username': 'LogWatcher',
            'icon_emoji': ':warning:'
        }
        response = requests.post(slack_config['webhook_url'], json=payload)
        response.raise_for_status()

    @retry_on_exception()
    def send_teams(self, message: str) -> None:
        """Send Microsoft Teams notification with retry logic."""
        teams_config = self.config['notifications']['teams']
        payload = {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'themeColor': 'FF0000',
            'summary': 'LogWatcher Alert',
            'sections': [{
                'activityTitle': 'LogWatcher Alert',
                'activitySubtitle': 'Pattern match detected',
                'text': message
            }]
        }
        response = requests.post(teams_config['webhook_url'], json=payload)
        response.raise_for_status()

    @retry_on_exception()
    def send_telegram(self, message: str) -> None:
        """Send Telegram notification with retry logic."""
        telegram_config = self.config['notifications']['telegram']
        url = f"https://api.telegram.org/bot{telegram_config['bot_token']}/sendMessage"
        payload = {
            'chat_id': telegram_config['chat_id'],
            'text': f"🚨 *LogWatcher Alert*\n\n{message}",
            'parse_mode': 'Markdown'
        }
        response = requests.post(url, json=payload)
        response.raise_for_status()

    def check_health(self) -> Dict[str, Any]:
        """Check the health status of all enabled notification services."""
        status = {}
        for service, handler in self.notifiers.items():
            config = self.config['notifications'].get(service, {})
            if config.get('enabled', False):
                try:
                    # Perform a lightweight check specific to each service
                    if service == 'email':
                        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                            server.starttls()
                            server.login(config['username'], config['password'])
                        status[service] = "OK"
                    elif service in ['slack', 'teams']:
                        requests.head(config['webhook_url']).raise_for_status()
                        status[service] = "OK"
                    elif service == 'telegram':
                        url = f"https://api.telegram.org/bot{config['bot_token']}/getMe"
                        requests.get(url).raise_for_status()
                        status[service] = "OK"
                except Exception as e:
                    status[service] = f"ERROR: {str(e)}"
            else:
                status[service] = "DISABLED"
        
        return status