import os
from django.utils.timezone import now
from django.core.mail import send_mail
from core.models import BaseUser,DeviceVideo,SOSEmails,SOSPhones
from customadmin.models import Plan
from datetime import timedelta
# from cloudinary.uploader import destroy
import logging
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
logger = logging.getLogger(__name__)

def my_scheduled_job():
    """
    Check and expire plans that have passed their expiry date, and notify users via email.
    """
    standard_plan = Plan.objects.get(name="Standard")  # Fetch the "standard" plan
    users_to_expire = BaseUser.objects.filter(expiry_date__lte=now(), plan__name__in=["Basic", "Pro"])

    for user in users_to_expire:
        # Update the user's plan and reset expiry date
        user.plan = standard_plan
        user.expiry_date = None
        user.save()
        logger.info(f"User {user.username}'s plan has expired. Assigned standard plan.")
        
        # Send email notification to the user
        try:
            # Render HTML content for the email
            context = {
                'user': user,
                'plan_name': standard_plan.name
            }
            html_content = render_to_string('plan_expire.html', context)

            # Create and send the email
            email = EmailMultiAlternatives(
                subject="Your Plan Has Expired",
                body="",  # Empty plain text body
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send()

            logger.info(f"Expiration email sent to {user.username} ({user.email}).")
        except Exception as e:
            logger.error(f"Failed to send expiration email to {user.username} ({user.email}): {e}")

def delete_old_videos():
    # Set a threshold date for 3 days ago
    threshold_date = now() - timedelta(days=3)
    
    # Get all videos older than the threshold date
    old_videos = DeviceVideo.objects.filter(uploaded_at__lte=threshold_date)

    for video in old_videos:
        if video.video:
            try:
                # Get the full file path of the video
                video_path = video.video.path  # This should return the local file path

                # Check if the video file exists, then delete it
                if os.path.exists(video_path):
                    os.remove(video_path)  # Remove the file from the local file system
                    video.video = None  # Clear the video field in the model
                    video.save()  # Save the changes to the database

                    logger.info(f"Successfully deleted video file: {video_path} for video ID {video.id}")
                else:
                    logger.error(f"Video file not found: {video_path} for video ID {video.id}")
            except AttributeError:
                logger.error(f"Video URL is missing or invalid for video ID {video.id}")
            except Exception as e:
                logger.error(f"Unexpected error while deleting video ID {video.id}: {e}")
            
def clear_expired_verification_tokens():
    """
    Clears expired verification tokens for both emails and phones.
    This function is triggered periodically by APScheduler.
    """
    now_time = now()
    expiration_threshold = timedelta(minutes=5)  # Tokens expire after 5 minutes

    # Clear expired tokens for emails
    expired_emails = SOSEmails.objects.filter(
        updated_at__lte=now_time - expiration_threshold,  # Check if last updated time is more than 5 minutes ago
        verification_token__isnull=False  # Only clear tokens that exist
    )
    expired_emails.update(verification_token=None)
    logger.info(f"Cleared {expired_emails.count()} expired email tokens.")

    # Clear expired tokens for phones
    expired_phones = SOSPhones.objects.filter(
        updated_at__lte=now_time - expiration_threshold,  # Check if last updated time is more than 5 minutes ago
        verification_token__isnull=False  # Only clear tokens that exist
    )
    expired_phones.update(verification_token=None)
    logger.info(f"Cleared {expired_phones.count()} expired phone tokens.")