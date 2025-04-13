from customadmin.views import *
from django.urls import path



app_name = 'customadmin'

urlpatterns = [
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('password_reset_request/',admin_password_reset_request, name='admin_password_reset_request'),
    path('dashboard/', admin_dashboard, name='admin_dashboard'),
    path('create-user/', CreateUserView.as_view(), name='create_user'),
    path('verify-email/<str:uidb64>/<str:token>/', verify_email, name='verify_email'),
    path('user-management/', UserManagementView.as_view(), name='user-management'),
    path('user/<uuid:user_id>/', user_view, name='user-view'),
    path('edit-user/<uuid:uuid>/', EditUserView.as_view(), name='edit_user'),
    path('block-user/<uuid:user_uuid>/', block_user, name='block_user'),
    path('unblock-user/<uuid:user_uuid>/', unblock_user, name='unblock_user'),
    path('delete-user/<uuid:user_uuid>/', delete_user, name='delete_user'),
    path('add-user-device/', add_user_device, name='add_user_device'),
    path('api/all-devices/', AdminDeviceManagementView.as_view(), name='button_management'),
    path('api/device/<int:device_id>/', admin_device_view, name='admin-device-view'),
    path('api/video/', all_video_list, name='all_video_list'),
    path('api/video/<uuid:user_id>/', video_list, name='video_list'),
    path('videos/<int:video_id>/', view_video, name='view_video'),
    path('video/delete/<int:video_id>/', delete_video, name='delete_video'),
    path('device/edit/<int:device_id>/', admin_edit_device, name='admin_edit_device'),
    path('download-csv/', download_csv, name='download_csv'),
    path('download_logs/', download_log_csv, name='download_log_csv'),
    path('download-user-csv/', download_user_csv, name='download_user_csv'),
    path('device/toggle-status/<int:device_id>/', toggle_device_status, name='toggle_device_status'),
    path('device/user/toggle-status/<int:device_id>/', toggle_user_device_status, name='toggle_user_device_status'),
    path('device/delete/<int:device_id>/', delete_device, name='delete_device'),   
    path('profile/',admin_profile, name='admin_profile'),
    path('admin-change-password/',admin_change_password, name='admin_change_password'),
    path('plans/', plan_management, name='plan_management'),
    path('plans/edit/<int:plan_id>/', edit_plan, name='edit_plan'),
    path('plans/delete/<int:plan_id>/', delete_plan, name='delete_plan'),
    path('transaction-history/', transaction_history, name='transaction_history'),
    path('transaction/<int:pk>/', transaction_detail_view, name='transaction_detail'),
    path('faq/', faq_list, name='faq_list'),
    path('faq/heading/delete/<int:id>/', delete_faq_heading, name='delete_faq_heading'),
    path('faq/update/<int:id>/', update_faq, name='update_faq'),
    path('faq/delete/<int:id>/', delete_faq, name='delete_faq'),
    path('faq/submission/', admin_faq_submission, name='admin_faq_submission'),
    path('faq/heading/<int:heading_id>/', faq_heading_details, name='faq_heading_details'),
    path('contactus/', get_in_touch_list, name='get_in_touch_list'), 
    path('leads/', contact_us_list, name='contact_us_list'),
    path('leads/<int:id>/', contact_us_detail, name='contact_us_detail'),
    path('static-content/', static_content_list, name='static_content_list'),
    path('content/<slug:slug>/', static_content_view, name='static_content'),
    path('create/', static_content_create_view, name='static_content_create'),
    path('static-content/delete/<slug:slug>/', delete_static_content, name='delete_static_content'),
    path('blogposts/', blogpost_list, name='blogpost_list'),
    path('blogposts/create/', blogpost_create, name='blogpost_create'),
    path('blogposts/<slug:slug>/', blogpost_detail, name='blogpost_detail'),
    path('blogposts/<slug:slug>/update/', blogpost_update, name='blogpost_update'),
    path('blogposts/<slug:slug>/delete/', blogpost_delete, name='blogpost_delete'),

    path('bulletedpoints/', bulletedpoint_list, name='bulletedpoint_list'),
    path('bulletedpoints/create/', bulletedpoint_create, name='bulletedpoint_create'),
    path('bulletedpoints/<int:pk>/update/', bulletedpoint_update, name='bulletedpoint_update'),
    path('bulletedpoints/<int:pk>/delete/', bulletedpoint_delete, name='bulletedpoint_delete'),
    path('manage_subscribers/', manage_subscribers, name='manage_subscribers'),
    path('toggle-subscription/<int:subscriber_id>/', toggle_subscription, name='toggle_subscription'),
 
    
    
] 