import csv
import os
from django.urls import reverse
from django.shortcuts import render,redirect,get_object_or_404
from django.contrib.auth import logout,update_session_auth_hash,get_user_model
from customadmin.forms import *    
from core.models import *
from .models import *
from django.views import View
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required,user_passes_test
from django.http import JsonResponse,HttpResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from datetime import datetime, timezone
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.utils.dateparse import parse_date
from customadmin.serializer import *
from customadmin.forms import *
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str,force_bytes
from django.utils.dateparse import parse_datetime
from rest_framework_simplejwt.tokens import AccessToken
from django.db.models import Count,Sum
from django.utils.timezone import now, localtime
from django.core.exceptions import ObjectDoesNotExist





class CustomLogoutView(View):
    def get(self, request, *args, **kwargs):    
        logout(request)
        return redirect('/')


def get_user_from_jwt(request):
    token = request.COOKIES.get('access_token')
    if not token:
        return None  # No token found

    try:
        access_token = AccessToken(token)
        user_id = access_token['user_id']
        return BaseUser.objects.get(id=user_id)
    except (BaseUser.DoesNotExist, KeyError):
        return None
   
def admin_dashboard(request):
    # Count total users and devices
    five_days_ago = now() - timedelta(days=5)   
    total_user = BaseUser.objects.filter(is_staff=False).count()
    total_devices = Device.objects.all().count()
    total_active_device = Device.objects.filter(device_status='Active').count()
    total_inactive_device = Device.objects.filter(device_status='Inactive').count()
    total_email_contacts = SOSEmails.objects.count()
    total_phone_contacts = SOSPhones.objects.count()
    total_contacts = total_email_contacts + total_phone_contacts
    total_plan_purchased = PaymentHistory.objects.filter(payment_status=PaymentStatus.SUCCEEDED.value).count()
    # Calculate total amount for payments with 'succeeded' status
    total_amount = PaymentHistory.objects.filter(payment_status=PaymentStatus.SUCCEEDED).aggregate(total=Sum('amount'))['total']

    # If no payments have succeeded, 'total' will be None, so handle that case
    total_amount = total_amount if total_amount is not None else 0
    total_transactions = PaymentHistory.objects.count()
    total_sms_event_triggered = NotificationLog.objects.filter(call_type='SMS').count()
    total_event_videos = DeviceVideo.objects.count()
    recent_onboarded = BaseUser.objects.filter(is_staff=False, created_at__gte=five_days_ago).order_by('-created_at')
    recent_onboarded_users = recent_onboarded.count()
    
    users = BaseUser.objects.exclude(is_superuser=True).order_by('-created_at')

    user_devices_count = {}
    for user in users:
        user_devices_count[user.id] = Device.objects.filter(user=user).count()

    # Get search and filter parameters from the query
    username_query = request.GET.get('username', '')
    date_from_str = request.GET.get('date_from', '')
    date_to_str = request.GET.get('date_to', '')
    status = request.GET.get('status', 'All')

    # Initialize queryset for users, excluding superusers

    # Apply username filter if search term is provided
    if username_query:
        users = users.filter(username__icontains=username_query)

    # Apply date filters if provided
    if date_from_str:
        try:
            date_from = parse_datetime(date_from_str)  # parse the datetime
            if date_from is None:
                raise ValueError("Invalid date format for 'date_from'.")
            users = users.filter(created_at__gte=date_from)
        except (ValueError, ValidationError):
            # Handle invalid date format or parsing errors
            pass

    if date_to_str:
        try:
            date_to = parse_datetime(date_to_str)  # parse the datetime
            if date_to is None:
                raise ValueError("Invalid date format for 'date_to'.")
            # Set date_to to the end of the day (23:59:59)
            date_to_end = datetime.combine(date_to, datetime.max.time())
            users = users.filter(created_at__lte=date_to_end)
        except (ValueError, ValidationError):
            # Handle invalid date format or parsing errors
            pass

    # Apply status filter if provided and not set to 'All'
    if status != 'All':
        if status == 'Active':
            users = users.filter(is_active=True)
        elif status == 'Inactive':
            users = users.filter(is_active=False)

    # Paginate the user results (20 users per page)
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page', 1)

    # Ensure page_number is a valid positive integer
    try:
        page_number = int(page_number)
        if page_number < 1:
            page_number = 1
    except (TypeError, ValueError):
        page_number = 1

    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver the first page.
        page_obj = paginator.page(1)
    except EmptyPage:
        # If page is out of range, deliver the last page.
        page_obj = paginator.page(paginator.num_pages)

    # Render the template with the necessary context
    return render(request, 'customadmin/admin-dashboard.html', {
        'total_user': total_user,
        'total_devices': total_devices,
        'total_active_device': total_active_device,
        'total_inactive_device': total_inactive_device,
        'total_contacts': total_contacts,
        'total_plan_purchased': total_plan_purchased,
        'total_amount':total_amount,
        'total_transactions':total_transactions,
        'total_sms_event_triggered': total_sms_event_triggered,
        'total_event_videos': total_event_videos,
        'recent_onboarded_users': recent_onboarded_users,
        'users': page_obj,
        'user_devices_count': user_devices_count,
        'username_filter': username_query,
        'date_from_filter': date_from_str,  # Keep original string format for rendering
        'date_to_filter': date_to_str,      # Keep original string format for rendering
        'status_filter': status,
    })


class UserManagementView(View):
    def get(self, request, *args, **kwargs):

        total_user = BaseUser.objects.filter(is_staff=False).count()
        total_active_users = BaseUser.objects.filter(is_active=True, is_staff=False).count()
        total_blocked_users = BaseUser.objects.filter(is_active=False, is_staff=False).count()
        # Get the search term from query parameters
        username_query = request.GET.get('username', '')
        date_from_str = request.GET.get('date_from', '')
        date_to_str = request.GET.get('date_to', '')
        status = request.GET.get('status', 'All')

        # Initialize queryset for users, excluding superusers
        users = BaseUser.objects.exclude(is_superuser=True).order_by('-created_at')

        user_devices_count = {}
        for user in users:
            user_devices_count[user.id] = Device.objects.filter(user=user).count()


        if username_query:
            users = users.filter(
                Q(username__icontains=username_query) | Q(email__icontains=username_query)
            )

        # Apply date filters if provided
        if date_from_str:
            try:
                date_from = parse_datetime(date_from_str)  # parse the datetime
                if date_from is None:
                    raise ValueError("Invalid date format for 'date_from'.")
                users = users.filter(created_at__gte=date_from)
            except (ValueError, ValidationError):
                # Handle invalid date format or parsing errors
                pass

        if date_to_str:
            try:
                date_to = parse_datetime(date_to_str)  # parse the datetime
                if date_to is None:
                    raise ValueError("Invalid date format for 'date_to'.")
                # Set date_to to the end of the day (23:59:59)
                date_to_end = datetime.combine(date_to, datetime.max.time())
                users = users.filter(created_at__lte=date_to_end)
            except (ValueError, ValidationError):
                # Handle invalid date format or parsing errors
                pass

        # Apply status filter if provided and not set to 'All'
        if status != 'All':
            if status == 'Active':
                users = users.filter(is_active=True)
            elif status == 'Blocked':
                users = users.filter(is_active=False)  


        # Paginate the results
        paginator = Paginator(users, 20)  # Show 20 users per page
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        return render(request, 'customadmin/admin_user_management.html', {
            'total_user': total_user,
            'total_active_users': total_active_users,
            'total_blocked_users': total_blocked_users,
            'users': page_obj,
            'user_devices_count': user_devices_count,
            'username_filter': username_query,
            'date_from_filter': date_from_str,  # Keep original string format for rendering
            'date_to_filter': date_to_str,      # Keep original string format for rendering
            'status_filter': status,
        })
    
def user_view(request, user_id):
    # Get the specific user, assuming UUID is being used for the user
    user = get_object_or_404(BaseUser, uuid=user_id)

    # Get filters from request
    device_name_filter = request.GET.get('device_name', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')
    status_filter = request.GET.get('status', 'All')

    # Start building the filters query, ensuring to filter by the current user
    filters = Q(user=user)  # Only fetch devices associated with the current user

    # Filter by device name if provided
   # Filter by device name if provided
    if device_name_filter:
        filters &= Q(device_name__icontains=device_name_filter)

    # Filter by device status if it's not 'All'
    if status_filter != 'All':
        filters &= Q(device_status=status_filter)

    # Filter by date range (created_at field)
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)  # parse datetime with time
            if date_from:
                filters &= Q(created_at__gte=date_from)
        except (ValueError, ValidationError):
            pass  # Ignore invalid date formats

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)  # parse datetime with time
            if date_to:
                # Set the end of the day for the date filter
                date_to_end = datetime.combine(date_to, datetime.max.time())
                filters &= Q(created_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass  # Ignore invalid date formats

    # Apply the filters to the Device queryset and ensure only the user's devices are shown
    devices = Device.objects.filter(filters).order_by('-created_at')

    # Paginate the results, 20 devices per page
    paginator = Paginator(devices, 20)  # Adjust per-page count if needed
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Pass the filters and paginated devices to the template for rendering
    context = {
        'user': user,
        'devices': page_obj,
        'device_name_filter': device_name_filter,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
        'status_filter': status_filter,
    }

    return render(request, 'customadmin/user_view.html', context)


def block_user(request, user_uuid):
    user = get_object_or_404(BaseUser, uuid=user_uuid)
    if request.method == 'POST':
        user.is_active = False
        user.save()
        return redirect('customadmin:user-management')
    return redirect('customadmin:user-management')

def unblock_user(request, user_uuid):
    user = get_object_or_404(BaseUser, uuid=user_uuid)
    if request.method == 'POST':
        user.is_active = True
        user.save()
        return redirect('customadmin:user-management')
    return redirect('customadmin:user-management')

class EditUserView(View):
    def get(self, request, uuid, *args, **kwargs):
        # Fetch the user object using the UUID
        user = get_object_or_404(BaseUser, uuid=uuid)
        
        # Initialize the form with the user instance
        form = UserEditForm(instance=user)
        
        # Render the template with the form and user context
        return render(request, 'customadmin/edit_user.html', {
            'form': form,
            'user': user
        })
    
    def post(self, request, uuid, *args, **kwargs):
        # Fetch the user object using the UUID
        user = get_object_or_404(BaseUser, uuid=uuid)
        
        # Create a form instance with the posted data and the user instance
        form = UserEditForm(request.POST, instance=user)
        
        if form.is_valid():
            phone_number = request.POST.get('phone_number', '')
            
            # Check if phone_number is provided
            if phone_number:
                # If phone_number exists, update it
                user.phone_number = phone_number
                user.save()

                # Redirect to the user management page after saving
                return redirect('customadmin:user-management')

            else:
                # If phone number is missing, add a form error
                form.add_error('phone_number', 'Phone number is required.')

        # Render the form again with errors if the form is not valid
        return render(request, 'customadmin/edit_user.html', {
            'form': form,
            'user': user
        })
    
def delete_user(request, user_uuid):
    user = get_object_or_404(BaseUser, uuid=user_uuid)
    if request.method == 'POST':
        user.delete()
        return redirect(reverse('customadmin:user-management'))
    else:
        return redirect(reverse('customadmin:user-management'))

def custom_logout_view(request):
    logout(request)
    return redirect('/')

def admin_profile(request):
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect(request.path + '?success=true')
    else:
        form = UserProfileForm(instance=request.user)

    return render(request, 'customadmin/admin_profile.html', {'form': form})

def admin_password_reset_request(request):
    if request.method == 'POST':
        form = forms.PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                send_mail(
                    'Password Reset Request',
                    f'Password reset request for email: {email}',
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                    fail_silently=False,
                )
                messages.success(request, 'Your password reset request has been sent to the admin.')
            except Exception as e:
                messages.error(request, f'Error sending email: {e}')
            return redirect('customadmin:admin_password_reset_request')
    else:
        form = forms.PasswordResetRequestForm()
    
    return render(request, 'customadmin/admin_password_reset_request.html', {'form': form})

def admin_change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user) 
            return redirect('customadmin:password_change_done') 
    else:
        form = CustomPasswordChangeForm(user=request.user)
    return render(request, 'customadmin/admin_password.html', {'form': form})


def password_change_done(request):
    return render(request, 'customadmin/password_change_done.html')


def add_user_device(request):
    User = get_user_model()  # Get the custom user model
    registered_users = User.objects.exclude(is_superuser=True)  # Query all registered users
    
    if request.method == 'POST':
        form = AdminDeviceForm(request.POST)
        if form.is_valid():
            try:
                form.save()  # Save the valid form data
                messages.success(request, 'Device added successfully!')
                return redirect('customadmin:button_management')  # Redirect to device list after saving
            except ValidationError as e:
                messages.error(request, f'Validation error: {e.message}')
        else:
            messages.error(request, 'Please correct the errors below.')

    else:
        form = AdminDeviceForm()

    return render(request, 'customadmin/add_user_device.html', {'form': form, 'registered_users': registered_users})



class AdminDeviceManagementView(View):
    def get(self, request, *args, **kwargs):
        device_name_filter = request.GET.get('device_name', '')
        date_from_filter = request.GET.get('date_from', '')
        date_to_filter = request.GET.get('date_to', '')
        status_filter = request.GET.get('status', 'All')

        # Build the query using Q objects
        filters = Q()

        # Filter by device name if provided
        if device_name_filter:
            filters &= Q(device_name__icontains=device_name_filter)

        # Filter by status if it's not 'All'
        if status_filter != 'All':
            filters &= Q(device_status=status_filter)

        # Filter by date range (created_at field)
        if date_from_filter:
            try:
                date_from = parse_datetime(date_from_filter)  # Use parse_datetime for flexibility
                if date_from:
                    filters &= Q(created_at__gte=date_from)
            except (ValueError, ValidationError):
                pass  # Handle invalid date format silently

        if date_to_filter:
            try:
                date_to = parse_datetime(date_to_filter)  # Use parse_datetime for flexibility
                if date_to:
                    # Set the end of the day for the date filter
                    date_to_end = datetime.combine(date_to, datetime.max.time())
                    filters &= Q(created_at__lte=date_to_end)
            except (ValueError, ValidationError):
                pass  # Handle invalid date format silently
                pass  # Handle invalid date format silently

        # Apply the filters to the Device queryset
        devices = Device.objects.filter(filters).select_related('user').order_by("-created_at")

        # Paginate the results
        paginator = Paginator(devices, 20)  # Show 20 devices per page
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        # Pass the filters and paginated devices to the template for rendering
        context = {
            'devices': page_obj,
            'device_name_filter': device_name_filter,
            'date_from_filter': date_from_filter,
            'date_to_filter': date_to_filter,
            'status_filter': status_filter,
        }

        return render(request, 'customadmin/button_management.html', context)

def admin_device_view(request, device_id):
    # Get the device by ID or return a 404 error if not found
    device = get_object_or_404(Device, id=device_id)

    # Initialize filters for logs
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')
    call_type_filter = request.GET.get('call_type', 'All')

    # Build the query for logs related to this device
    log_filters = Q(device=device)

    # Filter by date range
    if date_from_filter:
        try:
            date_from = datetime.strptime(date_from_filter, '%Y-%m-%d')
            log_filters &= Q(created_at__gte=date_from)
        except ValueError:
            pass  # Handle invalid date format silently

    if date_to_filter:
        try:
            date_to = datetime.strptime(date_to_filter, '%Y-%m-%d')
            date_to_end = datetime.combine(date_to, datetime.max.time())
            log_filters &= Q(created_at__lte=date_to_end)
        except ValueError:
            pass  # Handle invalid date format silently

    # Retrieve logs for the specified device applying the filters
    logs_queryset = NotificationLog.objects.filter(log_filters).order_by('-created_at')

    # Set up pagination
    paginator = Paginator(logs_queryset, 20)  # Show 20 logs per page
    page_number = request.GET.get('page')  # Get the page number from the request
    try:
        logs = paginator.get_page(page_number)  # Get the logs for that page
    except PageNotAnInteger:
        logs = paginator.get_page(1)  # If the page is not an integer, show the first page
    except EmptyPage:
        logs = paginator.get_page(paginator.num_pages)  # If the page is out of range, show the last page

    # Prepare context data to pass to the template
    context = {
        'device': device,
        'logs': logs,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
        'call_type_filter': call_type_filter,
    }

    # Render the template with the context
    return render(request, 'customadmin/admin_device_view.html', context)

def admin_edit_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    
    if request.method == 'POST':
        form = AdminDeviceForm(request.POST, instance=device)
        if form.is_valid():
            try:
                form.save()
                return redirect('customadmin:button_management')
            except ValidationError as e:
                messages.error(request, f'Validation error: {e}')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = AdminDeviceForm(instance=device)

    return render(request, 'customadmin/admin_edit_device.html', {'form': form, 'device': device})

def download_csv(request):
    # Retrieve filter values from GET parameters
    device_name_filter = request.GET.get('device_name', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')
    status_filter = request.GET.get('status', 'All')

    # Build the query
    filters = Q()
    
    # Filter by device name
    if device_name_filter:
        filters &= Q(device_name__icontains=device_name_filter)
    
    # Filter by status
    if status_filter != 'All':
        filters &= Q(device_status=status_filter)
    
    # Filter by date range
    if date_from_filter:
        try:
            date_from = datetime.strptime(date_from_filter, '%Y-%m-%d')
            filters &= Q(created_at__gte=date_from)
        except ValueError:
            pass

    if date_to_filter:
        try:
            date_to = datetime.strptime(date_to_filter, '%Y-%m-%d')
            filters &= Q(created_at__lte=date_to)
        except ValueError:
            pass

    # Apply filters to the queryset
    devices = Device.objects.filter(filters).select_related('user')

    # Create the CSV response
    response = HttpResponse(content_type='text/csv')

    # Generate filename with the current date
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f"devices_{current_date}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    
    # Write CSV headers
    writer.writerow([
        'Device Name', 'MAC Address',  'Device Status', 'User', 'Created At', 'Updated At'
    ])

    # Write data rows
    for device in devices:
        writer.writerow([
            device.device_name,
            device.mac_address,
            device.device_status,
            device.user.username if device.user else 'N/A',
            device.created_at,
            device.updated_at
        ])

    return response

def download_log_csv(request):
    # Retrieve filter values from GET parameters
    device_name_filter = request.GET.get('device_name', '')
    status_filter = request.GET.get('status', 'All')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    # Build the query
    filters = Q()

    # Filter by device name
    if device_name_filter:
        filters &= Q(device__device_name__icontains=device_name_filter)

    # Filter by status
    if status_filter != 'All':
        filters &= Q(status=status_filter)

    # Filter by date range
    if date_from_filter:
        try:
            date_from = datetime.strptime(date_from_filter, '%Y-%m-%d')
            filters &= Q(created_at__gte=date_from)
        except ValueError:
            pass

    if date_to_filter:
        try:
            date_to = datetime.strptime(date_to_filter, '%Y-%m-%d')
            filters &= Q(created_at__lte=date_to)
        except ValueError:
            pass

    # Apply filters to the queryset
    logs = NotificationLog.objects.filter(filters).select_related('device')

    # Create the CSV response
    response = HttpResponse(content_type='text/csv')

    # Generate filename with the current date
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f"notification_logs_{current_date}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)

    # Write CSV headers
    writer.writerow([
        'Device Name', 'MAC Address', 'Sent To', 'Status', 'Call Type', 'Created At', 'Updated At'
    ])

    # Write data rows
    for log in logs:
        writer.writerow([
            log.device.device_name if log.device else 'N/A',
            log.mac_address,
            log.sent_to,
            log.status,
            log.call_type if log.call_type else 'N/A',
            log.created_at,
            log.updated_at
        ])

    return response

def download_user_csv(request):
    # Retrieve filter values from GET parameters
    username_filter = request.GET.get('username', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')
    status_filter = request.GET.get('status', 'All')

    # Build the query
    filters = Q(is_superuser=False)  # Exclude superusers

    # Apply username filter
    if username_filter:
        filters &= Q(username__icontains=username_filter)

    # Apply status filter
    if status_filter != 'All':
        is_active = status_filter == 'Active'
        filters &= Q(is_active=is_active)

    # Apply date range filters
    if date_from_filter:
        try:
            date_from = datetime.strptime(date_from_filter, '%Y-%m-%d')
            filters &= Q(created_at__gte=date_from)
        except ValueError:
            pass

    if date_to_filter:
        try:
            date_to = datetime.strptime(date_to_filter, '%Y-%m-%d')
            filters &= Q(created_at__lte=date_to)
        except ValueError:
            pass

    # Fetch filtered users
    users = BaseUser.objects.filter(filters).values(
        'username', 'email', 'phone_number', 'is_active', 'created_at', 'last_login'
    )

    # Generate filename with the current date
    today_date = datetime.now().strftime('%Y-%m-%d')
    filename = f'users_{today_date}.csv'

    # Create the CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)

    # Write the header row
    writer.writerow([
        'Username',
        'Email',
        'Phone Number',
        'Status',
        'Created Date',
        'Last Login'
    ])

    # Write user data rows
    for user in users:
        writer.writerow([
            user.get('username', 'N/A'),
            user.get('email', 'N/A'),
            user.get('phone_number', 'N/A'),
            'Active' if user.get('is_active') else 'Blocked',
            user.get('created_at').strftime('%Y-%m-%d %H:%M') if user.get('created_at') else 'N/A',
            user.get('last_login').strftime('%Y-%m-%d %H:%M') if user.get('last_login') else 'N/A'
        ])

    return response
@require_POST
def delete_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.delete()
    return redirect('customadmin:button_management') 



@csrf_protect
def toggle_device_status(request, device_id):
    if request.method == 'POST':
        device = get_object_or_404(Device, id=device_id)
        # Toggle status
        if device.device_status == 'Active':
            device.device_status = 'Inactive'
        else:
            device.device_status = 'Active'
        
        device.save()
        return JsonResponse({'status': 'success', 'redirect_url': reverse('customadmin:button_management')})
    return JsonResponse({'status': 'error'}, status=400)


@csrf_protect
def toggle_user_device_status(request, device_id):
    if request.method == 'POST':
        device = get_object_or_404(Device, id=device_id)
        
        # Toggle status
        device.device_status = 'Blocked' if device.device_status == 'Active' else 'Active'
        device.save()

        user_id = device.user.uuid  # Assuming user has a uuid attribute

        return JsonResponse({'status': 'success', 'redirect_url': reverse('customadmin:user-view', kwargs={'user_id': user_id})})
    
    return JsonResponse({'status': 'error'}, status=400)

def plan_management(request):
    plans = Plan.objects.all().order_by('-created_at')  

    if request.method == 'POST':
        form = PlanForm(request.POST)
        if form.is_valid():
            # Create a new plan instance without saving it yet
            plan = form.save(commit=False)
            
            # Calculate stream_length from the cleaned data
            minutes = form.cleaned_data['stream_length_minutes']
            seconds = form.cleaned_data['stream_length_seconds']

            minutes = int(minutes) if minutes else 0
            seconds = int(seconds) if seconds else 0
            plan.stream_length = timedelta(minutes=minutes, seconds=seconds)
            
            plan.save()  # Save the plan to the database
            messages.success(request, 'Plan added successfully!')
            return redirect('customadmin:plan_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = PlanForm()

    context = {
        'plans': plans,
        'form': form,
    }
    return render(request, 'customadmin/plan_management.html', context)

def edit_plan(request, plan_id):
    """
    View to edit a plan in the admin panel.
    """
    plan = get_object_or_404(Plan, id=plan_id)

    # Calculate minutes and seconds from stream_length
    stream_length_seconds = plan.stream_length.total_seconds() if plan.stream_length else 0
    stream_length_minutes = int(stream_length_seconds // 60)
    stream_length_remaining_seconds = int(stream_length_seconds % 60)

    if request.method == 'POST':
        form = PlanForm(request.POST, instance=plan)
        if form.is_valid():
            try:
                # Save the form but do not commit yet
                plan = form.save(commit=False)
            
                # Calculate stream_length from the cleaned data
                minutes = form.cleaned_data['stream_length_minutes']
                seconds = form.cleaned_data['stream_length_seconds']

                minutes = int(minutes) if minutes else 0
                seconds = int(seconds) if seconds else 0
                plan.stream_length = timedelta(minutes=minutes, seconds=seconds)
                
                plan.save() 
                messages.success(request, 'Plan updated successfully!')
                return redirect('customadmin:plan_management')  # Redirect after saving
            except Exception as e:
                messages.error(request, f"An unexpected error occurred: {e}")
        else:
            messages.error(request, 'Please correct the errors in the form.')
    else:
        form = PlanForm(instance=plan, initial={
            'stream_length_minutes': stream_length_minutes,
            'stream_length_seconds': stream_length_remaining_seconds,
        })

    context = {
        'form': form,
        'plan': plan,
        'stream_length_minutes': stream_length_minutes,
        'stream_length_seconds': stream_length_remaining_seconds,
    }
    return render(request, 'customadmin/edit_plan.html', context)





def delete_plan(request, plan_id):
    plan = get_object_or_404(Plan, id=plan_id)
    plan.delete()
    return redirect('customadmin:plan_management')

def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(BaseUser, pk=uid)
    except (TypeError, ValueError, OverflowError):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_verified = True
        user.save()

        # Prepare the credentials email
        login_link = f"{settings.SITE_URL}"
        subject = 'Your Login Credentials for ICE-Button System'
        message = render_to_string('customadmin/credentials_email.html', {
            'username': user.username,
            'password': 'Mobiloitte@1',
            'login_link': login_link  
        })

        try:
            email = EmailMultiAlternatives(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,  
                [user.email]
            )
            email.attach_alternative(message, "text/html")  
            email.send()  
            
            return render(request, 'email/success_verification.html')
        except Exception as e:
            messages.error(request, f'Error sending credentials email: {e}')
        
        return redirect('login') 
    else:
        messages.error(request, 'The verification link is invalid or has expired.')

    return render(request, 'email/email_verification_result.html')


class CreateUserView(View):
    def get(self, request):
        form = CreateUserForm()
        plans = Plan.objects.all()  
        return render(request, 'customadmin/create_user.html', {'form': form, 'plans': plans})

    def post(self, request):
        form = CreateUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_verified = False  # Set the user as inactive until email is verified
            user.set_password('Mobiloitte@1')  # Set the default password
            user.save()

            try:
                standard_plan = Plan.objects.get(name="Standard")  # Assuming the standard plan is named "standard"
                user.plan = standard_plan
                user.save()
            except Plan.DoesNotExist:
                messages.error(request, 'Default standard Plan not found. Please configure the standard Plan.')
            # Create the verification link
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            verification_link = f"{settings.SITE_URL}/admin/verify-email/{uid}/{token}/"

            # Prepare the email
            subject = 'Verify Your Account for ICE-Button System'
            message = render_to_string('email/email_verification.html', {
                'user': user,
                'verification_link': verification_link,
            })

            try:
                email = EmailMultiAlternatives(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,  
                    [user.email]
                )
                email.attach_alternative(message, "text/html")  
                email.send()  # Send the email

                messages.success(request, 'User created successfully and verification email sent.')
            except Exception as e:
                messages.error(request, f'Error sending email: {e}')

            return redirect('customadmin:create_user')
        else:
            messages.error(request, 'Error creating user. Please check the form.')

        plans = Plan.objects.all()  # Query again in case of errors
        return render(request, 'customadmin/create_user.html', {'form': form, 'plans': plans})

    

def transaction_history(request):
    # Retrieve filter parameters from GET request
    transaction_id = request.GET.get('transaction_id', '').strip()
    date_from_filter = request.GET.get('date_from', '').strip()
    date_to_filter = request.GET.get('date_to', '').strip()
    status = request.GET.get('status', 'All').strip()

    # Start with all transactions
    transactions = PaymentHistory.objects.all().order_by('-processed_at')

    # Apply filters using Q objects
    filters = Q()

    if transaction_id:
        filters &= Q(payment_id__icontains=transaction_id)

    # Apply date range filters using parse_datetime
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)
            if date_from:
                filters &= Q(created_at__gte=date_from)
        except (ValueError, ValidationError):
            pass  # Handle invalid date format silently

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)
            if date_to:
                # Set the end of the day for the date filter
                date_to_end = datetime.combine(date_to, datetime.max.time())
                filters &= Q(created_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass  # Handle invalid date format silently

    if status and status != 'All':
        filters &= Q(payment_status__iexact=status)

    # Apply the combined filters
    transactions = transactions.filter(filters)

    # Paginate the results
    paginator = Paginator(transactions, 20)  # 20 transactions per page
    page_number = request.GET.get('page')
    try:
        page_obj = paginator.get_page(page_number)
    except (EmptyPage, PageNotAnInteger):
        page_obj = paginator.get_page(1)

    # Pass filters and pagination object to the template
    context = {
        'SITE_URL': settings.SITE_URL,
        'page_obj': page_obj,
        'transaction_id_filter': transaction_id,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
        'status_filter': status,
    }
    return render(request, 'customadmin/transactions_history.html', context)

def transaction_detail_view(request, pk):
    """
    Function-based view to display transaction details.
    """
    transaction = get_object_or_404(PaymentHistory, pk=pk)
    context = {
        'transaction': transaction
    }
    return render(request, 'invoice/invoice.html', context)

def all_video_list(request):
    # Get the filter parameters from GET request
    device_name_filter = request.GET.get('device_name', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    filters = Q()  # No user_id filter here for the admin view
    
    # Filter by device name if provided
    if device_name_filter:
        filters &= Q(device__device_name__icontains=device_name_filter)
    
    # Filter by date range using parse_datetime
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)  # Use parse_datetime for better flexibility
            if date_from:
                filters &= Q(uploaded_at__gte=date_from)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)  # Use parse_datetime for better flexibility
            if date_to:
                # Set the end of the day for the date filter
                date_to_end = datetime.combine(date_to, datetime.max.time())
                filters &= Q(uploaded_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    # Query for all videos with the applied filters
    videos = DeviceVideo.objects.filter(filters).order_by('-uploaded_at')

    # Pagination
    paginator = Paginator(videos, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    context = {
        'videos': page_obj,
        'device_name_filter': device_name_filter,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
    }

    return render(request, 'customadmin/all_video_list.html', context)


def video_list(request, user_id):
    # Ensure user_id is treated as a string
    user = get_object_or_404(BaseUser, uuid=user_id)
    user_id_str = str(user_id)  # Convert UUID to string

    device_name_filter = request.GET.get('device_name', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    filters = Q(user__uuid=user_id_str)  # Use the string representation of user_id
    # Apply device name filter if provided
    if device_name_filter:
        filters &= Q(device__device_name__icontains=device_name_filter)
    
    # Apply date range filters using parse_datetime
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)  # Use parse_datetime for flexibility
            if date_from:
                filters &= Q(uploaded_at__gte=date_from)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)  # Use parse_datetime for flexibility
            if date_to:
                # Set the end of the day for the date filter
                date_to_end = datetime.combine(date_to, datetime.max.time())
                filters &= Q(uploaded_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    videos = DeviceVideo.objects.filter(filters).order_by('-uploaded_at')


    paginator = Paginator(videos, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    context = {
        'user': user,
        'videos': page_obj,
        'device_name_filter': device_name_filter,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
    }

    return render(request, 'customadmin/video_list.html', context)

def view_video(request, video_id):
    # Fetch the video using the video_id (assuming you're passing video_id as a URL parameter)
    video = get_object_or_404(DeviceVideo, id=video_id)

    # Pass the video instance to the template
    return render(request, 'customadmin/view_video.html', {'video': video})


def delete_video(request, video_id):
    video = get_object_or_404(DeviceVideo, id=video_id)
    video_path = video.video.path

    if os.path.exists(video_path):
        os.remove(video_path)

    video.delete()

    return redirect(reverse('customadmin:video_list', kwargs={'user_id': video.user.uuid}))


def get_in_touch_list(request):
    # Get filter parameters from GET request
    name_filter = request.GET.get('name', '')
    email_filter = request.GET.get('email', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    filters = Q()

    # Filter by name if provided
    if name_filter:
        filters &= Q(name__icontains=name_filter)

    # Filter by email if provided
    if email_filter:
        filters &= Q(email__icontains=email_filter)

    # Filter by date range using parse_datetime
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)
            if date_from:
                filters &= Q(created_at__gte=date_from)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)
            if date_to:
                # Set the end of the day for the date filter
                date_to_end = datetime.combine(date_to, datetime.max.time())
                filters &= Q(created_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    # Query for `GetInTouch` entries with the applied filters
    messages = GetInTouch.objects.filter(filters).order_by('-created_at')

    # Pagination
    paginator = Paginator(messages, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    context = {
        'messages': page_obj,
        'name_filter': name_filter,
        'email_filter': email_filter,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
    }

    return render(request, 'customadmin/get_in_touch_list.html', context)

def admin_faq_submission(request):
    if request.method == 'POST':
        # Get data from the request
        heading_id = request.POST.get('heading')
        new_heading_title = request.POST.get('new_heading')
        new_heading_description = request.POST.get('new_description', '')
        question = request.POST.get('question')
        answer = request.POST.get('answer')

        # Validation
        errors = {}
        if not heading_id and not new_heading_title:
            errors['heading'] = 'Please select an existing heading or create a new one.'
        if not question:
            errors['question'] = 'Question is required.'
        if not answer:
            errors['answer'] = 'Answer is required.'
        if new_heading_title and len(new_heading_title) > 255:
            errors['new_heading'] = 'Heading title must not exceed 255 characters.'

        if errors:
            headings = FAQHeading.objects.all()
            return render(request, 'customadmin/admin_faq_submission.html', {
                'errors': errors,
                'headings': headings,
                'selected_heading': heading_id,
                'new_heading': new_heading_title,
                'new_description': new_heading_description,
                'question': question,
                'answer': answer,
            })

        # Create or get heading
        heading = None
        if heading_id:
            heading = FAQHeading.objects.filter(id=heading_id).first()
        elif new_heading_title:
            heading, created = FAQHeading.objects.get_or_create(
                title=new_heading_title,
                defaults={'description': new_heading_description}
            )

        if not heading:
            messages.error(request, "An error occurred while processing the heading.")
            return redirect('customadmin:admin_faq_submission')

        # Save the FAQ
        FAQs.objects.create(heading=heading, question=question, answer=answer)
        messages.success(request, "FAQ successfully created!")
        return redirect('customadmin:admin_faq_submission')

    # Render the empty form for GET request
    headings = FAQHeading.objects.all()
    return render(request, 'customadmin/admin_faq_submission.html', {'headings': headings})

def faq_list(request):
    # Fetching FAQ headings with the count of questions related to each heading
    faq_headings = FAQHeading.objects.annotate(total_questions=Count('faq_s')).all()

    context = {
        'faq_headings': faq_headings
    }

    return render(request, 'customadmin/admin_faqs.html', context)

def faq_heading_details(request, heading_id):
    # Get the FAQHeading instance with the given heading_id
    heading = get_object_or_404(FAQHeading, id=heading_id)
    faqs = heading.faq_s.all()  # Get all FAQs related to this heading
    context = {
        'heading': heading,
        'faqs': faqs
    }
    return render(request, 'customadmin/faq_heading_details.html', context)


def delete_faq_heading(request, id):
    # Get the FAQHeading object to delete
    faq_heading = get_object_or_404(FAQHeading, id=id)

    if request.method == "POST":
        # If the form is submitted (POST), delete the FAQ heading
        faq_heading.delete()
        return redirect(reverse('customadmin:faq_list'))  # Redirect to FAQ list page after deletion

    # If the request method is not POST, just redirect to the FAQ list page
    return redirect(reverse('customadmin:faq_list'))


def update_faq(request, id):
    # Get the FAQ object to update
    faq = get_object_or_404(FAQs, id=id)

    if request.method == "POST":
        # Bind the form to the submitted data
        form = FAQUpdateForm(request.POST, instance=faq)
        if form.is_valid():
            # Save the updated FAQ object
            form.save()
            return redirect(reverse('customadmin:faq_heading_details', args=[faq.heading.id]))  # Redirect to FAQ list page
    else:
        # Display the form pre-filled with the current data
        form = FAQUpdateForm(instance=faq)

    return render(request, 'customadmin/faq_update.html', {'form': form, 'faq': faq})

def delete_faq(request, id):
    # Get the FAQ object to delete
    faq = get_object_or_404(FAQs, id=id)

    if request.method == "POST":
        # If the form is submitted (POST), delete the FAQ
        faq.delete()
        return redirect(reverse('customadmin:faq_heading_details', args=[faq.heading.id]))  # Redirect to FAQ list page after deletion

    # If the request method is not POST, just redirect to the FAQ list page
    return redirect(reverse('customadmin:faq_heading_details', args=[faq.heading.id]))

def contact_us_list(request):
    # Get the filter values from GET parameters
    name_filter = request.GET.get('name', '')
    email_filter = request.GET.get('email', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    filters = Q()

    # Filter by name if provided
    if name_filter:
        filters &= Q(name__icontains=name_filter)

    # Filter by email if provided
    if email_filter:
        filters &= Q(email__icontains=email_filter)

    # Filter by date range using parse_datetime
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)
            if date_from:
                # Make date_from aware
                if timezone.is_naive(date_from):
                    date_from = timezone.make_aware(date_from)
                filters &= Q(created_at__gte=date_from)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)
            if date_to:
                # Make date_to aware
                if timezone.is_naive(date_to):
                    date_to = timezone.make_aware(date_to)
                # Set the end of the day for the date filter
                date_to_end = datetime.combine(date_to, datetime.max.time())
                if timezone.is_naive(date_to_end):
                    date_to_end = timezone.make_aware(date_to_end)
                filters &= Q(created_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass  # Handle invalid date formats silently

    contact_us_entries = ContactUs.objects.filter(filters).order_by('-created_at')

    paginator = Paginator(contact_us_entries, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    return render(request, 'customadmin/contact_us_list.html', {'page_obj': page_obj})


def contact_us_detail(request, id):
    contact_us_entry = get_object_or_404(ContactUs, id=id)  # Fetch contact entry by ID
    return render(request, 'customadmin/contact_us_detail.html', {'contact_us_entry': contact_us_entry})


def static_content_list(request):
    name_filter = request.GET.get('title', '')
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    filters = Q()

    # Filter by title if provided
    if name_filter:
        filters &= Q(title__icontains=name_filter)


    # Filter by date range using parse_datetime
    if date_from_filter:
        try:
            date_from = parse_datetime(date_from_filter)
            if date_from:
                if timezone.is_naive(date_from):
                    date_from = timezone.make_aware(date_from)
                filters &= Q(created_at__gte=date_from)
        except (ValueError, ValidationError):
            pass

    if date_to_filter:
        try:
            date_to = parse_datetime(date_to_filter)
            if date_to:
                if timezone.is_naive(date_to):
                    date_to = timezone.make_aware(date_to)
                date_to_end = datetime.combine(date_to, datetime.max.time())
                if timezone.is_naive(date_to_end):
                    date_to_end = timezone.make_aware(date_to_end)
                filters &= Q(created_at__lte=date_to_end)
        except (ValueError, ValidationError):
            pass

    static_content_list = StaticContent.objects.filter(filters).order_by('-created_at')
    paginator = Paginator(static_content_list, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    return render(request, 'customadmin/static_content_list.html', {
        'page_obj': page_obj,
        'title_filter': name_filter,  # Pass the filter values to the template
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
    })

from django.utils import timezone
def static_content_create_view(request):
    if request.method == 'POST':
        # Create a new StaticContent object without using a form
        title = request.POST.get('title')
        slug = request.POST.get('slug')
        body = request.POST.get('new_text')
        meta_title = request.POST.get('meta_title')
        meta_description = request.POST.get('meta_description')

        # Create a new content instance
        new_content = StaticContent(
            title=title,
            slug=slug,
            body=body,
            meta_title=meta_title,
            meta_description=meta_description,
            updated_at=timezone.now()  # Set the current time as the updated_at
        )
        
        # Save the new content instance
        new_content.save()

        # Redirect to a success page or content list
        return redirect('customadmin:static_content_list')  # Replace with your success page URL or content list URL

    return render(request, 'customadmin/static_content_create.html')


def static_content_view(request, slug):
    content = get_object_or_404(StaticContent, slug=slug)

    if request.method == 'POST':
        # Update the content object manually without using a form
        content.title = request.POST.get('title', content.title)
        content.slug = request.POST.get('slug', content.slug)  # Update only if you want it to be editable
        content.body = request.POST.get('new_text', content.body)
        content.meta_title = request.POST.get('meta_title', content.meta_title)
        content.meta_description = request.POST.get('meta_description', content.meta_description)
        content.updated_at = timezone.now()  # Update the updated_at field
        
        # Save the content
        content.save()

        # Redirect to success page or reload the current page
        return redirect('customadmin:static_content_list')  # Replace with the actual URL name for the success page

    return render(request, 'customadmin/static_content.html', {'content': content})

def delete_static_content(request, slug):
    content = get_object_or_404(StaticContent, slug=slug)

    if request.method == 'POST':
        # Delete the content object
        content.delete()
        # Redirect to a success page or content list
        return redirect('customadmin:static_content_list')  # Replace with the actual URL name for your success page or content list
    
    return redirect('customadmin:static_content_list')


def blogpost_list(request):
    posts = BlogPost.objects.all()
    return render(request, 'customadmin/blogpost_list.html', {'posts': posts})

def blogpost_detail(request, slug):
    post = get_object_or_404(BlogPost, slug=slug)
    return render(request, 'customadmin/blogpost_detail.html', {'post': post})


from django.forms import modelformset_factory

def blogpost_create(request):
    BlogImageFormSet = modelformset_factory(BlogImage, form=BlogImageForm, extra=1, can_delete=True)

    if request.method == 'POST':
        form = BlogPostForm(request.POST, request.FILES)
        formset = BlogImageFormSet(request.POST, request.FILES, queryset=BlogImage.objects.none())

        if form.is_valid() and formset.is_valid():
            # Save blog post
            blogpost = form.save(commit=False)
            blogpost.slug = slugify(blogpost.title)
            blogpost.save()
            form.save_m2m()  # Save many-to-many relationships

            # Save each extra image and associate with the blog post
            for extra_image_form in formset:
                if extra_image_form.cleaned_data and not extra_image_form.cleaned_data.get('DELETE', False):
                    extra_image = extra_image_form.save()
                    blogpost.extra_images.add(extra_image)

            return redirect('customadmin:blogpost_list')
        else:
            # Debug errors
            print("BlogPostForm Errors:", form.errors)
            print("BlogImageFormSet Errors:", formset.errors)
    else:
        form = BlogPostForm()
        formset = BlogImageFormSet(queryset=BlogImage.objects.none())

    return render(request, 'customadmin/blogpost_form.html', {
        'form': form,
        'formset': formset,
    })


def blogpost_update(request, slug):
    post = get_object_or_404(BlogPost, slug=slug)
    if request.method == 'POST':
        form = BlogPostForm(request.POST, request.FILES, instance=post)
        if form.is_valid():
            form.save()
            return redirect('customadmin:blogpost_detail', slug=post.slug)
    else:
        form = BlogPostForm(instance=post)
    return render(request, 'customadmin/blogpost_form.html', {'form': form})

def blogpost_delete(request, slug):
    post = get_object_or_404(BlogPost, slug=slug)
    if request.method == 'POST':
        post.delete()
        return redirect('customadmin:blogpost_list')
    return render(request, 'customadmin/blogpost_confirm_delete.html', {'post': post})

# BulletedPoint Views

def bulletedpoint_list(request):
    points = BulletedPoint.objects.all()
    return render(request, 'customadmin/bulletedpoint_list.html', {'points': points})

def bulletedpoint_create(request):
    if request.method == 'POST':
        form = BulletedPointForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('customadmin:bulletedpoint_list')
    else:
        form = BulletedPointForm()
    return render(request, 'customadmin/bulletedpoint_form.html', {'form': form})

def bulletedpoint_update(request, pk):
    point = get_object_or_404(BulletedPoint, pk=pk)
    if request.method == 'POST':
        form = BulletedPointForm(request.POST, request.FILES, instance=point)
        if form.is_valid():
            form.save()
            return redirect('customadmin:bulletedpoint_list')
    else:
        form = BulletedPointForm(instance=point)
    return render(request, 'customadmin/bulletedpoint_form.html', {'form': form})

def bulletedpoint_delete(request, pk):
    point = get_object_or_404(BulletedPoint, pk=pk)
    if request.method == 'POST':
        point.delete()
        return redirect('customadmin:bulletedpoint_list')
    return render(request, 'customadmin/bulletedpoint_confirm_delete.html', {'point': point})


def terms_and_conditions(request):
    return render(request, 'terms-and-conditions.html')




def manage_subscribers(request):
    # Get the search filter from request (if any)
    search_filter = request.GET.get('search', '')
    
    # Get the status filter from request (if any)
    status_filter = request.GET.get('status', 'All')
    
    # Get the date filters from request (if any)
    date_from_filter = request.GET.get('date_from', '')
    date_to_filter = request.GET.get('date_to', '')

    # Start building the query
    subscribers = Subscriber.objects.all()


    # Apply search filter (name or email)
    if search_filter:
        subscribers = subscribers.filter(
            Q(name__icontains=search_filter) | Q(email__icontains=search_filter)
        )

    # Apply status filter
    if status_filter != 'All':
        subscribers = subscribers.filter(status=status_filter)
    
    # Apply date range filters
    if date_from_filter:
        subscribers = subscribers.filter(subscribed_at__gte=date_from_filter)
    if date_to_filter:
        subscribers = subscribers.filter(subscribed_at__lte=date_to_filter)

    # Add an ordering to avoid the unordered warning
    subscribers = subscribers.order_by('subscribed_at')  # or any other field you prefer


    # Pagination
    paginator = Paginator(subscribers, 10)  # Show 10 subscribers per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Context to pass to template
    context = {
        'subscribers': page_obj,
        'search_filter': search_filter,
        'status_filter': status_filter,
        'date_from_filter': date_from_filter,
        'date_to_filter': date_to_filter,
    }

    return render(request, 'customadmin/manage_subscribers.html', context)

def toggle_subscription(request, subscriber_id):
    subscriber = get_object_or_404(Subscriber, id=subscriber_id)
    subscriber.toggle_status()  # Using the toggle method to change status
    status_message = 'subscribed' if subscriber.status == 'subscribed' else 'unsubscribed'
    return redirect('customadmin:manage_subscribers')
