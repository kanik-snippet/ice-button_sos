from django.conf import settings
from django.db import models
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
import uuid
from django.utils.translation import gettext_lazy as _
from django.core.validators import EmailValidator
from django.utils.http import urlsafe_base64_encode
from core.tokens import subscriber_token_generator
from django.urls import reverse
from ckeditor.fields import RichTextField
    

from django.utils.text import slugify
class Plan(models.Model):
    MONTHLY = 'monthly'
    YEARLY = 'yearly'
    PLAN_CHOICES = [
        (MONTHLY, 'Monthly'),
        (YEARLY, 'Yearly'),
    ]
    name = models.CharField(max_length=50, unique=True)  # Default name for the plan
    max_emails = models.PositiveIntegerField()  # Default max emails allowed
    max_phone_numbers = models.PositiveIntegerField()  # Default max phone numbers allowed
    max_button = models.PositiveIntegerField()  # Default max buttons allowed
    subscription_type = models.CharField(
        max_length=10,
        choices=PLAN_CHOICES,
        default=MONTHLY,
    )
    stream = models.BooleanField(default=True)
    stream_length = models.DurationField(default=timedelta(minutes=1, seconds=30))
    cost = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    
    def get_yearly_cost(self):
        """Calculate the yearly cost based on the subscription type."""
        if self.subscription_type == self.MONTHLY:
            return self.cost * 12  # Multiply monthly cost by 12 for yearly total
        elif self.subscription_type == self.YEARLY:
            return self.cost  # Return the yearly cost as is
        return 0.00  # Default return if no valid subscription type is set
    

class BaseUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, plan=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, plan=plan, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, **extra_fields)

class BaseUser(AbstractBaseUser, PermissionsMixin):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150, blank=True, null=True)
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, null=True, blank=True)  
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expiry_date = models.DateTimeField(null=True, blank=True, help_text="The date when the current plan expires.")

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = BaseUserManager()

    def __str__(self):
        return self.username

    class Meta:
        ordering = ['username']

class User(BaseUser):
    user_type = models.CharField(max_length=50, default="user")

    def __str__(self):
        return f"User: {self.username}"

    class Meta:
        db_table = 'user_table'

class Admin(BaseUser):
    admin_role = models.CharField(max_length=50, default="admin")

    def __str__(self):
        return f"Admin: {self.username}"

    class Meta:
        db_table = 'admin_table'



# Possible Payment Methods
class PaymentMethod(models.TextChoices):
    CARD = 'card', _('Card')
    UPI = 'upi', _('UPI')
    WALLET = 'wallet', _('Wallet')
    BANK_TRANSFER = 'bank_transfer', _('Bank Transfer')
    OTHER = 'other', _('Other')

class PaymentStatus(models.TextChoices):
    PENDING = 'pending', _('Pending')
    SUCCEEDED = 'succeeded', _('Succeeded')
    FAILED = 'failed', _('Failed')
    CANCELLED = 'cancelled', _('Cancelled')
    REFUNDED = 'refunded', _('Refunded')
    DISPUTED = 'disputed', _('Disputed')

class PaymentHistory(models.Model):
    user = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, related_name='payments', null=True)
    plan_name = models.CharField(max_length=254)
    amount = models.FloatField()
    payment_status = models.CharField(max_length=20, choices=PaymentStatus.choices, default=PaymentStatus.PENDING, help_text="The status of the payment.")
    payment_method = models.CharField(max_length=50, choices=PaymentMethod.choices, default=PaymentMethod.CARD, help_text="Method used for payment.")
    currency = models.CharField(max_length=3, default='INR', help_text="Currency code (INR, USD, etc.)")
    provider_order_id = models.CharField(max_length=40, default=0)
    payment_id = models.CharField(max_length=36, default=0)
    signature_id = models.CharField(max_length=128, default=0)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, help_text="Timestamp when payment was initiated.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Timestamp when payment details were last updated.")
    processed_at = models.DateTimeField(blank=True, null=True, help_text="Timestamp when the payment was processed successfully.")

    def __str__(self):
        return f"{self.id}- {self.plan_name}- {self.payment_status}"

# class PaymentHistory(models.Model):
#     # User and Plan information
#     user = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='payments')
#     plan_name = models.CharField(max_length=255, help_text="Name of the plan associated with the payment.")
    
#     # Payment details
#     amount = models.DecimalField(max_digits=15, decimal_places=2, help_text="The amount paid by the user.")
#     currency = models.CharField(max_length=3, default='INR', help_text="Currency code (INR, USD, etc.)")
#     payment_intent_id = models.CharField(max_length=255, unique=True, help_text="Payment gateway transaction ID.")
    
#     # Payment method and status
#     payment_method = models.CharField(max_length=50, choices=PaymentMethod.choices, default=PaymentMethod.CARD, help_text="Method used for payment.")
#     payment_status = models.CharField(max_length=20, choices=PaymentStatus.choices, default=PaymentStatus.PENDING, help_text="The status of the payment.")
    
#     # Tracking customer and gateway responses
#     customer_email = models.EmailField(help_text="The email of the customer making the payment.")
#     stripe_response_code = models.CharField(max_length=255, blank=True, null=True, help_text="Payment gateway response code.")
#     gateway_fees = models.DecimalField(max_digits=15, decimal_places=2, default=0.00, help_text="Fees charged by payment gateway.")
#     metadata = models.JSONField(default=dict, blank=True, null=True, help_text="Additional metadata from the payment gateway.")
    
#     # Refund, Dispute, and Tracking failed attempts
#     refunded_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0.00, help_text="Amount refunded if payment was refunded.")
#     dispute_reason = models.CharField(max_length=255, blank=True, null=True, help_text="Reason for dispute if payment is disputed.")
#     failed_attempts = models.IntegerField(default=0, help_text="Number of failed payment attempts before success.")
    
#     # Timestamps
#     created_at = models.DateTimeField(auto_now_add=True, help_text="Timestamp when payment was initiated.")
#     updated_at = models.DateTimeField(auto_now=True, help_text="Timestamp when payment details were last updated.")
#     processed_at = models.DateTimeField(blank=True, null=True, help_text="Timestamp when the payment was processed successfully.")

#     # Optional Fields for Invoicing, Taxes, and Discount
#     tax_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0.00, help_text="Tax amount if applicable.")
#     discount_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0.00, help_text="Discount amount if applicable.")
    
#     # Status Logs
#     status_logs = models.JSONField(default=list, blank=True, null=True, help_text="Logs of status changes for auditing.")
    
#     class Meta:
#         indexes = [
#             models.Index(fields=['user', 'payment_status']),
#             models.Index(fields=['payment_intent_id']),
#         ]
#         verbose_name = 'Payment History'
#         verbose_name_plural = 'Payment Histories'
    
#     def __str__(self):
#         return f"Payment of {self.amount} {self.currency} for {self.user.username} (Status: {self.payment_status})"
    
#     def get_status(self):
#         """
#         Helper method to return human-readable status.
#         """
#         return dict(PaymentStatus.choices).get(self.payment_status, 'Unknown')

#     def update_status(self, new_status: str):
#         """
#         Helper method to update the payment status and log the transition.
#         """
#         if new_status != self.payment_status:
#             self.status_logs.append({
#                 'status': new_status,
#                 'timestamp': self.updated_at,
#             })
#             self.payment_status = new_status
#             self.save()

#     def process_refund(self, refund_amount: float):
#         """
#         Handle the refund logic and update relevant fields.
#         """
#         if self.payment_status == PaymentStatus.SUCCEEDED:
#             self.payment_status = PaymentStatus.REFUNDED
#             self.refunded_amount = refund_amount
#             self.save()

#     def mark_as_processed(self):
#         """
#         Mark the payment as successfully processed and log the time.
#         """
#         self.payment_status = PaymentStatus.SUCCEEDED
#         self.processed_at = self.updated_at
#         self.save()
    
class FAQHeading(models.Model):
    title = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True, help_text="Optional description for the FAQ heading.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class FAQs(models.Model):
    heading = models.ForeignKey(FAQHeading, on_delete=models.CASCADE, related_name='faq_s')
    question = models.TextField()
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.question

    


class StaticContent(models.Model):
    # Core fields
    title = models.CharField(max_length=255, unique=True, help_text="The title of the content.")
    slug = models.SlugField(
        max_length=255, 
        unique=True, 
        help_text="Unique identifier for the content (e.g., 'terms-and-conditions')."
    )
    body = RichTextField(help_text="The content to display, supports rich text formatting.") 

    # Metadata fields
    meta_title = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="Optional meta title for SEO. Defaults to the title."
    )
    meta_description = models.TextField(
        blank=True, 
        null=True, 
        help_text="Optional meta description for SEO."
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, help_text="The date and time the content was created.")
    updated_at = models.DateTimeField(auto_now=True, help_text="The date and time the content was last updated.")

    class Meta:
        verbose_name = "Static Content"
        verbose_name_plural = "Static Contents"
        ordering = ["-updated_at"]

    def save(self, *args, **kwargs):
        # Auto-generate slug if not provided
        if not self.slug:
            self.slug = slugify(self.title) # type: ignore
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title

    def meta_title_or_fallback(self):
        """Returns meta title if available, otherwise falls back to title."""
        return self.meta_title or self.title

from ckeditor.fields import RichTextField
from django.utils import timezone  # Add this import

# class emailContent(models.Model):
#     # Core fields
#     title = models.CharField(
#         max_length=255,
#         unique=True,
#         default="Default Title",
#         help_text="The title of the content."
#     )
#     slug = models.SlugField(
#         max_length=255,
#         unique=True,
#         blank=True,
#         help_text="Unique identifier for the content (e.g., 'terms-and-conditions')."
#     )
#     body = RichTextField(
#         default="Default body content.",
#         help_text="The content to display, supports rich text formatting."
#     )  # Added default value

#     # Metadata fields
#     meta_title = models.CharField(
#         max_length=255, 
#         blank=True, 
#         null=True, 
#         help_text="Optional meta title for SEO. Defaults to the title."
#     )
#     meta_description = models.TextField(
#         blank=True, 
#         null=True, 
#         help_text="Optional meta description for SEO."
#     )

#     # Timestamps
#     created_at = models.DateTimeField(
#         default=timezone.now, 
#         help_text="The date and time the content was created."
#     )
#     updated_at = models.DateTimeField(
#         default=timezone.now, 
#         help_text="The date and time the content was last updated."
#     )

#     class Meta:
#         verbose_name = "Email Content"
#         verbose_name_plural = "Email Contents"
#         ordering = ["-updated_at"]

#     def save(self, *args, **kwargs):
#         if not self.slug:
#             self.slug = slugify(self.title)
#         super().save(*args, **kwargs)

#     def __str__(self):
#         return self.title

#     def meta_title_or_fallback(self):
#         return self.meta_title or self.title


class Subscriber(models.Model):
    STATUS_CHOICES = [
        ('subscribed', 'Subscribed'),
        ('unsubscribed', 'Unsubscribed'),
        ('pending', 'Pending'),
    ]
    
    name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='subscribed')
    subscribed_at = models.DateTimeField(auto_now_add=True)
    unsubscribed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return self.name or self.email

    def toggle_status(self):
        """Toggles subscription status between subscribed and unsubscribed."""
        if self.status == 'subscribed':
            self.status = 'unsubscribed'
            self.unsubscribed_at = timezone.now()
        else:
            self.status = 'subscribed'
        self.save()

    def get_name_from_user(self):
        """Fetch the name from the BaseUser model if the user exists, with fallback handling."""
        try:
            user = BaseUser.objects.get(email=self.email)
            if user.first_name and user.last_name:
                return f"{user.first_name} {user.last_name}"
            elif user.first_name:
                return user.first_name
            elif user.username:
                return user.username
        except BaseUser.DoesNotExist:
            pass  # No user found with the provided email
        return ""  # Return empty string if no user is found

    def save(self, *args, **kwargs):
        """Override save method to assign name field based on user or fallback to an empty string."""
        if not self.name:  # Assign name only if it is not already set
            self.name = self.get_name_from_user() or "Subscriber"
        super().save(*args, **kwargs)


    def generate_unsubscribe_url(self, request=None):
        """Generates a full URL for unsubscribing, including the domain."""
        token = subscriber_token_generator.make_token(self)  # Use the custom token generator
        uid = urlsafe_base64_encode(str(self.pk).encode('utf-8'))
        unsubscribe_path = reverse('unsubscribe', kwargs={'uidb64': uid, 'token': token})
        
        if request:
            # If request is passed, build an absolute URL including the domain
            unsubscribe_url = request.build_absolute_uri(unsubscribe_path)
        else:
            # Fallback to domain from settings if request is not available
            unsubscribe_url = f"{settings.SITE_URL}{unsubscribe_path}"

        return unsubscribe_url


    def subscribe(self):
        """Subscribes the user."""
        self.status = 'subscribed'
        self.unsubscribed_at = None
        self.save()

    def unsubscribe(self):
        """Unsubscribes the user."""
        self.status = 'unsubscribed'
        self.unsubscribed_at = timezone.now()
        self.save()