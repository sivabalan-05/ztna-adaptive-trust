"""Alert delivery.

SMTP when it is configured, console plus the ``system_logs`` table otherwise.
Every alert is written to the ``alerts`` table by the caller regardless — this
module is only about *pushing* it somewhere a human will see it, and a failure
to deliver must never roll back the security event itself.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from functools import lru_cache
from typing import Protocol

from sqlalchemy.orm import Session

from app.core.config import settings
from app.external.base import ProviderInfo
from app.models.base import utcnow
from app.models.enums import AlertSeverity, LogLevel
from app.models.system_log import SystemLog

logger = logging.getLogger(__name__)

_SEVERITY_TO_LOG_LEVEL = {
    AlertSeverity.INFO: LogLevel.INFO,
    AlertSeverity.LOW: LogLevel.INFO,
    AlertSeverity.MEDIUM: LogLevel.WARNING,
    AlertSeverity.HIGH: LogLevel.ERROR,
    AlertSeverity.CRITICAL: LogLevel.CRITICAL,
}


@dataclass(frozen=True)
class Notification:
    subject: str
    body: str
    severity: AlertSeverity
    recipients: tuple[str, ...] = ()


class NotificationProvider(Protocol):
    info: ProviderInfo

    def send(self, notification: Notification) -> bool: ...


class ConsoleNotification:
    """Logs the alert. The development and offline-demo default."""

    info = ProviderInfo(
        name="console",
        live=False,
        detail="Alerts are logged and written to system_logs; no mail is sent.",
    )

    def send(self, notification: Notification) -> bool:
        level = _SEVERITY_TO_LOG_LEVEL.get(notification.severity, LogLevel.INFO)
        logger.log(
            getattr(logging, level.value, logging.INFO),
            "ALERT [%s] %s :: %s",
            notification.severity.value, notification.subject, notification.body,
        )
        return True


class SMTPNotification:
    """Sends mail, degrading to the console provider on any failure."""

    def __init__(self) -> None:
        self._fallback = ConsoleNotification()
        self.info = ProviderInfo(
            name="smtp",
            live=True,
            detail=f"SMTP via {settings.smtp_host}:{settings.smtp_port}",
        )

    def send(self, notification: Notification) -> bool:
        recipients = notification.recipients
        if not recipients:
            logger.debug("No recipients for '%s'; logging instead.", notification.subject)
            return self._fallback.send(notification)

        message = EmailMessage()
        message["Subject"] = f"[ZTNA {notification.severity.value}] {notification.subject}"
        message["From"] = settings.smtp_from
        message["To"] = ", ".join(recipients)
        message.set_content(notification.body)

        try:
            with smtplib.SMTP(settings.smtp_host or "", settings.smtp_port, timeout=10) as smtp:
                smtp.starttls()
                if settings.smtp_user and settings.smtp_password:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(message)
        except Exception:
            logger.exception("SMTP delivery failed for '%s'", notification.subject)
            self._fallback.send(notification)
            return False
        return True


@lru_cache(maxsize=1)
def get_provider() -> NotificationProvider:
    if settings.smtp_host:
        logger.info("Notifications: SMTP via %s", settings.smtp_host)
        return SMTPNotification()
    logger.info("Notifications: console + system_logs (no SMTP configured)")
    return ConsoleNotification()


def notify(
    db: Session | None,
    *,
    subject: str,
    body: str,
    severity: AlertSeverity,
    recipients: tuple[str, ...] = (),
    context: dict[str, object] | None = None,
) -> bool:
    """Deliver a notification and record the attempt.

    Never raises: an undeliverable alert is logged, not propagated into the
    request that produced it.
    """
    notification = Notification(
        subject=subject, body=body, severity=severity, recipients=recipients
    )
    try:
        delivered = get_provider().send(notification)
    except Exception:
        logger.exception("Notification provider raised for '%s'", subject)
        delivered = False

    if db is not None:
        db.add(
            SystemLog(
                created_at=utcnow(),
                level=_SEVERITY_TO_LOG_LEVEL.get(severity, LogLevel.INFO),
                logger="notification",
                message=subject,
                context={
                    "body": body,
                    "severity": severity.value,
                    "recipients": list(recipients),
                    "delivered": delivered,
                    "provider": get_provider().info.name,
                    **(context or {}),
                },
            )
        )
    return delivered
