from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.urls import reverse
from .models import *
from django.utils.html import format_html

# Admin configuration for User model
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'is_active', 'created_at', 'plan')
    search_fields = ('username', 'email')
    list_filter = ('is_active', 'plan')

# Admin configuration for Admin model
class AdminAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'is_active', 'admin_role', 'created_at')
    search_fields = ('username', 'email')
    list_filter = ('is_active', 'admin_role')

# Admin configuration for Plan model
class PlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'max_emails', 'max_phone_numbers', 'max_button', 'stream', 'stream_length', 'cost', 'created_at', 'updated_at')
    search_fields = ('name',)
    list_filter = ('stream',)
    ordering = ('name',)
    fieldsets = (
        (None, {'fields': ('name', 'max_emails', 'max_phone_numbers', 'max_button', 'stream', 'stream_length', 'cost')}),
    )

@admin.register(PaymentHistory)
class PaymentHistoryAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'user', 'plan_name_display', 'created_at', 'payment_status', 'payment_method'
    )
    list_filter = ('payment_status', 'payment_method', 'created_at')

    def plan_name_display(self, obj):
        return obj.plan_name or 'No Plan'
    plan_name_display.short_description = 'Plan Name'

class FAQIsInline(admin.TabularInline):
    model = FAQs
    extra = 1  # Number of empty forms for new FAQ items

@admin.register(FAQHeading)
class FAQHeadingAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_at', 'updated_at')
    search_fields = ('title',)
    inlines = [FAQIsInline]

@admin.register(StaticContent)
class StaticContentAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'created_at', 'updated_at')
    search_fields = ('title', 'slug')

    
admin.site.register(BaseUser)
admin.site.register(Plan, PlanAdmin)
admin.site.register(User, UserAdmin)
admin.site.register(Admin, AdminAdmin)

class SubscriberAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'status', 'subscribed_at', 'unsubscribed_at')
    list_filter = ('status', 'subscribed_at')
    search_fields = ('name', 'email')

admin.site.register(Subscriber, SubscriberAdmin)

