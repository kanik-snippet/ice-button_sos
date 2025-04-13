from django.utils import timezone
from django.db import models
from customadmin.models import BaseUser
from django.utils.text import slugify
from ckeditor.fields import RichTextField 
from cloudinary.models import CloudinaryField





class FollowUs(models.Model):
    facebook = models.URLField("Facebook URL", max_length=200, blank=True, null=True)
    instagram = models.URLField("Instagram URL", max_length=200, blank=True, null=True)
    telegram = models.URLField("Telegram URL", max_length=200, blank=True, null=True)
    twitter = models.URLField("Twitter URL", max_length=200, blank=True, null=True)
    pinterest = models.URLField("Pinterest URL", max_length=200, blank=True, null=True)

    class Meta:
        verbose_name = "Follow Us Link"
        verbose_name_plural = "Follow Us Links"

    def __str__(self):
        return "Follow Us Links"
       
# Profile Model
class Profile(models.Model):
    user = models.OneToOneField(BaseUser, on_delete=models.CASCADE, related_name="profile")
    profile_photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)
    designation = models.CharField(max_length=50, blank=True)
    name = models.CharField(max_length=100)
    bio = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} ({self.user.email})"

class BlogComment(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    topic = models.CharField(max_length=100, blank=True, null=True)
    comment = models.TextField()
    blog = models.ForeignKey('BlogPost', on_delete=models.CASCADE, related_name='comments')
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.name} on {self.blog.title}"
    
class BulletedPoint(models.Model):
    text = models.TextField()
    image = models.ImageField(upload_to="bulleted_images/", blank=True, null=True)

    def __str__(self):
        return self.text[:30]    
    
class BlogPost(models.Model):
    CATEGORY_CHOICES = [
        ('tech', 'Technology & Innovation'),
        ('cyber', 'Cybersecurity'),
        ('disaster', 'Disaster Preparedness'),
        ('business', 'Business & Entrepreneurship'),
        ('safety', 'Personal Safety & Security'),
        ('health', 'Health & Wellness'),
        ('lifestyle', 'Lifestyle & Productivity'),
        ('community', 'Community Engagement'),
        ('tutorials', 'Tech Reviews & Tutorials'),
        ('environmental', 'Environmental Sustainability'),
    ]
    
    title = models.CharField(max_length=200)
    description = RichTextField(null=True, blank=True)
    content = RichTextField() 
    created_by = models.ForeignKey('Profile', on_delete=models.CASCADE,null=True, blank=True)  # User's profile for the name
    created_at = models.DateTimeField(default=timezone.now)  # Timestamp of when the post is created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp of when the post was last updated
    image = CloudinaryField('image', null=True, blank=True)  # Main image for the post
    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
        default='general',  # Default category
    )
    slug = models.SlugField(unique=True, max_length=255)  # Unique slug for each blog post

    # Optional quote for the post (if included in the template)
    quote_text = models.CharField(max_length=500, blank=True, null=True)
    quote_author = models.ForeignKey('Profile', on_delete=models.SET_NULL, null=True, blank=True, related_name="quotes")

    # For tags related to this blog post
    tags = models.ManyToManyField('Tag', related_name='blog_posts', blank=True)
    bulleted_points = models.ManyToManyField(BulletedPoint, related_name="blog_posts", blank=True)
    # For additional images (like the extra images shown in the template)
    extra_images = models.ManyToManyField('BlogImage', related_name='posts', blank=True)

    # Extra content (same content condition as the main content)
    extra_content = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        # Auto-generate the slug if not provided
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    class Meta:
        ordering = ['-created_at']  # Display the newest post first

    
class Tag(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


class BlogImage(models.Model):
    image = CloudinaryField('extra_images')  # Separate Cloudinary storage for extra images
    description = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.description or f"Image {self.id}"
