from django.contrib import admin
from .models import *
# Register your models here.
from django.utils import timezone
from django.utils.html import format_html

# Profile Admin
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'designation')
    search_fields = ('name', 'user__email', 'designation')
    list_filter = ('designation',)

# BlogPost Admin
class BlogPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'created_by', 'created_at', 'updated_at', 'slug', 'is_published')
    search_fields = ('title', 'content', 'created_by__name', 'created_by__user__email')
    list_filter = ('category', 'created_at', 'updated_at')
    prepopulated_fields = {'slug': ('title',)}  # Auto-generate slug based on title

    # Make `updated_at` read-only
    readonly_fields = ('updated_at',)

    # Define fields shown in the admin form
    fields = (
        'title', 'slug', 'description', 'content', 
        'created_by', 'created_at', 'updated_at', 
        'category', 'tags', 'image', 
        'extra_images', 'quote_text', 'quote_author', 
        'bulleted_points', 'extra_content'
    )

    def is_published(self, obj):
        return obj.created_at is not None
    is_published.boolean = True
    
    def image_preview(self, obj):
        """Display a thumbnail of the main blog image."""
        if obj.image:
            return format_html('<img src="{}" style="width: 50px; height: 50px;" />', obj.image.url)
        return "No Image"
    image_preview.short_description = "Image Preview"

    # Override save_model to set `created_at` if not provided
    def save_model(self, request, obj, form, change):
        if not obj.created_at:
            obj.created_at = timezone.now()  # Use current time if no date is provided
        super().save_model(request, obj, form, change)

# Tag Admin
class TagAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

# BulletedPoint Admin
class BulletedPointAdmin(admin.ModelAdmin):
    list_display = ('text', 'image')
    search_fields = ('text',)

    def image_preview(self, obj):
        """Display a thumbnail of additional images."""
        if obj.image:
            return format_html('<img src="{}" style="width: 50px; height: 50px;" />', obj.image.url)
        return "No Image"
    image_preview.short_description = "Image Preview"

# BlogImage Admin
class BlogImageAdmin(admin.ModelAdmin):
    list_display = ('image', 'description')
    search_fields = ('description',)

@admin.register(FollowUs)
class FollowUsAdmin(admin.ModelAdmin):
    list_display = ("facebook", "instagram", "telegram", "twitter", "pinterest")
    search_fields = ("facebook", "instagram", "twitter", "pinterest")
    list_filter = ("facebook", "instagram", "twitter", "pinterest")  

@admin.register(BlogComment)
class BlogCommentAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'is_approved', 'created_at')
    list_filter = ('is_approved', 'created_at')
    actions = ['approve_comments', 'reject_comments']

    def approve_comments(self, request, queryset):
        queryset.update(is_approved=True)

    def reject_comments(self, request, queryset):
        queryset.update(is_approved=False)

admin.site.register(Profile, ProfileAdmin)
admin.site.register(BlogPost, BlogPostAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(BulletedPoint, BulletedPointAdmin)
admin.site.register(BlogImage, BlogImageAdmin)