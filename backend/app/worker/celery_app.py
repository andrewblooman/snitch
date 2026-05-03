from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "snitch",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.worker.tasks", "app.worker.notification_tasks", "app.worker.github_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    beat_schedule={
        "weekly-scan-all-scheduled": {
            "task": "app.worker.tasks.weekly_scan_all",
            # Every Sunday at 02:00 UTC
            "schedule": crontab(hour=2, minute=0, day_of_week=0),
        },
        "poll-github-security-alerts": {
            "task": "app.worker.github_tasks.poll_github_security_task",
            # Every 5 minutes
            "schedule": crontab(minute="*/5"),
        },
    },
)
