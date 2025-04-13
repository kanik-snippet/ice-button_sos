from django.contrib import admin
from .models import *

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('device_name', 'user', 'mac_address', 'device_status', 'created_at', 'updated_at')
    list_filter = ('device_status', 'created_at', 'updated_at')
    search_fields = ('device_name', 'mac_address', 'user__username')
    filter_horizontal = ('sos_emails', 'sos_phones')

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('event_id', 'user', 'device', 'created_at')
    search_fields = ('event_id', 'user__username', 'device__device_name')
    list_filter = ('created_at',)

@admin.register(NotificationLog)
class NotificationLogAdmin(admin.ModelAdmin):
    list_display = ('device', 'mac_address', 'sent_to', 'status', 'call_type', 'created_at', 'updated_at')
    search_fields = ('mac_address', 'device__device_name', 'sent_to')
    list_filter = ('status', 'call_type', 'created_at', 'updated_at')

class DeviceVideoAdmin(admin.ModelAdmin):
    # Displaying fields in the admin list view
    list_display = ('user', 'device', 'video', 'uploaded_at', 'event', 'video_link')  # Added video_link
    
    # Adding filters to make it easier to filter videos by user and device
    list_filter = ('user', 'device', 'uploaded_at', 'event')
    
    # Adding search functionality
    search_fields = ('user__username', 'device__device_name', 'video')

    # Make video field clickable to directly play the video
    readonly_fields = ('video',)
    
    # Adding a custom method to display the video file link in the admin list
    def video_link(self, obj):
        return obj.video.url if obj.video else "No Video"
    video_link.short_description = 'Video URL'
    
    # Make the video URL clickable
    list_display_links = ('user', 'video_link')

# Register the model and its admin view
admin.site.register(DeviceVideo, DeviceVideoAdmin)

@admin.register(SOSEmails)
class SOSEmailsAdmin(admin.ModelAdmin):
    list_display = ('user', 'emails', 'name', 'relation', 'is_verified', 'created_at', 'updated_at')
    search_fields = ('emails', 'user__username', 'name', 'relation')
    list_filter = ('is_verified', 'created_at', 'updated_at')

@admin.register(SOSPhones)
class SOSPhonesAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone_numbers', 'name', 'relation', 'is_verified', 'allow_call', 'allow_sms', 'allow_whatsapp', 'created_at', 'updated_at')
    search_fields = ('phone_numbers', 'user__username', 'name', 'relation')
    list_filter = ('is_verified', 'allow_call', 'allow_sms', 'allow_whatsapp', 'created_at', 'updated_at')

class UserLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'log_message', 'created_at', 'read')
    list_filter = ('created_at', 'read', 'user')
    search_fields = ('user__username', 'log_message')
    ordering = ('-created_at',)
    actions = ['mark_as_read']

    def mark_as_read(self, request, queryset):
        """Mark selected logs as read."""
        queryset.update(read=True)
        self.message_user(request, "Selected logs have been marked as read.")
    mark_as_read.short_description = "Mark selected logs as read"

admin.site.register(UserLog, UserLogAdmin)


@admin.register(DeviceStream)
class DeviceStreamAdmin(admin.ModelAdmin):
    list_display = ('device', 'stream_key', 'created_at', 'updated_at')  # Fields to display in the list view
    search_fields = ('device__device_name', 'device__mac_address', 'stream_key')  # Enable search functionality
    list_filter = ('created_at', 'updated_at')  # Add filters for created and updated timestamps
    ordering = ('-created_at',)  # Default ordering by the newest records first
    raw_id_fields = ('device',)  # Use a lookup widget for the device field
