import uuid
from django.db import models
from customadmin.models import BaseUser

class Device(models.Model):
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
    ]

    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE)
    device_name = models.CharField(max_length=255, blank=True)
    mac_address = models.CharField(max_length=17, blank=True, unique=True)
    message = models.CharField(max_length=50, null=True)
    description = models.TextField(blank=True, null=True)
    device_status = models.CharField(max_length=8, choices=STATUS_CHOICES, default='Active')

    # Many-to-Many fields for associating contacts with devices
    sos_emails = models.ManyToManyField('SOSEmails', blank=True, related_name='devices')
    sos_phones = models.ManyToManyField('SOSPhones', blank=True, related_name='devices')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.device_name
    
class Event(models.Model):
    event_id = models.CharField(max_length=100,unique=True)
    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event {self.event_id} by {self.user}"
    


class NotificationLog(models.Model):
    event = models.ForeignKey(Event, on_delete=models.SET_NULL, null=True, blank=True, related_name='notifications')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)  
    mac_address = models.CharField(max_length=100) 
    sent_to = models.CharField(max_length=50)
    status = models.CharField(max_length=20) 
    call_type = models.CharField(max_length=50, blank=True, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.device.device_name} - {self.call_type} - {self.status}"
    

class DeviceVideo(models.Model):
    event = models.ForeignKey(Event, on_delete=models.SET_NULL, null=True, blank=True, related_name='devicevideo')
    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True, related_name='videos')
    video = models.FileField(upload_to='device_videos/%(user)s/', null=True, blank=True)
    video_url = models.URLField(max_length=5000,blank=True, null=True)  # Add the video URL field
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Video from {self.user.username} - {self.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')}"

    def save(self, *args, **kwargs):
        # Dynamically set the upload path for the video file based on the user's username
        if self.video:
            self.video.field.upload_to = f'device_videos/{self.user.username}/'
        super().save(*args, **kwargs)
    
    def set_video_url(self, video_url):
        """Set the Cloudinary video URL after uploading to Cloudinary."""
        self.video_url = video_url
        self.save()
        
class SOSEmails(models.Model):
    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='sos_emails')
    contact_reference = models.UUIDField(default=uuid.uuid4, editable=False, null=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    relation = models.CharField(max_length=50, null=True, blank=True)
    emails = models.EmailField(max_length=255)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'emails']),  # Add index for faster lookups by user and email
        ]
        unique_together = ('user', 'emails')
    def __str__(self):
        return f"{self.user.username} - {self.emails}"

class SOSPhones(models.Model):
    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='sos_phones')
    contact_reference = models.UUIDField(editable=False, null=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    relation = models.CharField(max_length=50, null=True, blank=True)
    phone_numbers = models.CharField(max_length=20)
    country_code = models.CharField(max_length=5, null=True, blank=True) 
    verification_token = models.CharField(max_length=255, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    allow_whatsapp = models.BooleanField(default=False)
    allow_sms = models.BooleanField(default=False)
    allow_call = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiration = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'phone_numbers']),  # Add index for faster lookups by user and phone number
        ]
        unique_together = ('user', 'phone_numbers')
    
    def __str__(self):
        return f"{self.user.username} - {self.phone_numbers}"

class ContactUs(models.Model):
    name = models.CharField(max_length=100)  # Full Name
    organization = models.CharField(max_length=200, blank=True, null=True)  # Organization Name
    email = models.EmailField()  
    phone = models.CharField(max_length=15, blank=True, null=True)  # Phone Number
    ice_quantity = models.PositiveIntegerField(blank=True, null=True)  # ICE Button Quantity
    installation_date = models.DateField(blank=True, null=True)  # Installation Date
    city = models.CharField(max_length=100, blank=True, null=True)  # City
    subject = models.CharField(max_length=200, blank=True, null=True)  # Subject
    message = models.TextField()  # Message
    created_at = models.DateTimeField(auto_now_add=True)  # Created At
    updated_at = models.DateTimeField(auto_now=True)  # Updated At

    def __str__(self):
        return self.name
    
class GetInTouch(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False)
    email = models.EmailField(blank=False, null=False)
    phone_number = models.CharField(max_length=15,blank=True,null=True)
    subject = models.CharField(max_length=200, blank=True, null=True)
    message = models.TextField(blank=False, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Message from {self.name} ({self.email})"

    class Meta:
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone_number']),
        ]

        ordering = ['-created_at']  # Newest entries first


class UserLog(models.Model):
    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE)
    log_message = models.CharField(max_length=1024)
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)  # To track if the notification is read or not

    def __str__(self):
        return f"{self.user.username} - {self.log_message}"

class DeviceStream(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)  # Reference to the device
    stream_key = models.CharField(max_length=255)  # Store the stream key
    is_stream = models.BooleanField(default=True)  
    created_at = models.DateTimeField(auto_now_add=True)  # When the entry was created
    updated_at = models.DateTimeField(auto_now=True)  # When the entry was last updated

    class Meta:
        unique_together = ('device',)  # Ensure that each device can have only one stream key at a time

    def __str__(self):
        return f"StreamKey for {self.device.device_name if self.device else 'Unknown Device'}"