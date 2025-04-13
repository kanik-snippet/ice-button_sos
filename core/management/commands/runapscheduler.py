from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from django_apscheduler.jobstores import DjangoJobStore, register_events
from django.core.management.base import BaseCommand
from core.tasks import my_scheduled_job, delete_old_videos,clear_expired_verification_tokens
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Runs the APScheduler for periodic tasks."

    def handle(self, *args, **options):
        scheduler = BlockingScheduler()
        scheduler.add_jobstore(DjangoJobStore(), "default")

        # Schedule the plan expiry task
        scheduler.add_job(
            my_scheduled_job,
            trigger=CronTrigger(hour=0, minute=0),  # Run daily at midnight
            id="expire_plans",
            max_instances=1,
            replace_existing=True,
        )
        logger.info("Added job 'expire_plans'.")

        # Schedule the video deletion task
        scheduler.add_job(
            delete_old_videos,
            trigger=CronTrigger(hour=1, minute=0),  # Run daily at 1 AM
            id="delete_old_videos",
            max_instances=1,
            replace_existing=True,
        )
        logger.info("Added job 'delete_old_videos'.")

        # Schedule the expired verification token cleanup task
        scheduler.add_job(
            clear_expired_verification_tokens,
            trigger=CronTrigger(minute="*/1"),  # Run every minute
            id="clear_expired_verification_tokens",
            max_instances=1,
            replace_existing=True,
        )
        logger.info("Added job 'clear_expired_verification_tokens'.")

        # Register the events for Django
        register_events(scheduler)

        try:
            logger.info("Starting scheduler...")
            scheduler.start()
        except KeyboardInterrupt:
            logger.info("Stopping scheduler...")
            scheduler.shutdown()
            logger.info("Scheduler stopped successfully.")