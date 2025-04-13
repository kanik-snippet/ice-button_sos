import requests
from django.conf import settings
from .models import UserLog
from user_agents import parse




def send_whatsapp_message(phone_number, message):
    """
    Send a WhatsApp message to the given phone number using the WhatsApp Business API (Facebook Graph API).
    """
    url = f"https://graph.facebook.com/v21.0/{settings.WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        'Authorization': f'Bearer {settings.WHATSAPP_ACCESS_TOKEN}',  # Replace with actual access token
        'Content-Type': 'application/json'
    }

    # WhatsApp API payload for sending a template message
    data = {
        "messaging_product": "whatsapp",
        "to": phone_number,
        "type": "template",
        "template": {
            "name": "ice_button_alert",  
            "language": {
                "code": "en"  
            }
        }
    }

    try:
        # Send the POST request to the Facebook Graph API
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            # Successful response
            return True
        else:
            # Log the error response if the status is not 200
            print(f"Error sending message to {phone_number}: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        # Catch network errors or other request issues
        print(f"Error sending message to {phone_number}: {str(e)}")
        raise e


def send_whatsapp_messages_to_multiple_numbers(phone_numbers, message):
    """
    Send WhatsApp messages to multiple phone numbers.
    Returns a list of failed phone numbers and the error reasons if any failures occur.
    """
    failed_numbers = []

    for phone_number in phone_numbers:
        try:
            # Attempt to send the message to each phone number
            success = send_whatsapp_message(phone_number, message)
            if not success:
                failed_numbers.append({"phone": phone_number, "error": "Failed to send message"})
        except Exception as e:
            # Collect the failed phone number and error message
            failed_numbers.append({"phone": phone_number, "error": str(e)})

    return failed_numbers



def get_device_name(user_agent):
    """Parse the User-Agent string to get a user-friendly device name."""
    user_agent_parsed = parse(user_agent)
    if user_agent_parsed.is_mobile:
        device_type = "Mobile"
    elif user_agent_parsed.is_tablet:
        device_type = "Tablet"
    elif user_agent_parsed.is_pc:
        device_type = "PC"
    else:
        device_type = "Unknown Device"
    
    return f"{device_type} ({user_agent_parsed.os.family} {user_agent_parsed.os.version_string}) - {user_agent_parsed.browser.family} {user_agent_parsed.browser.version_string}"

def get_client_ip(request):
    """Extract the real client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()  # Take the first IP in the list
    else:
        ip = request.META.get('REMOTE_ADDR', '')  # Fallback to REMOTE_ADDR
    return ip

def get_location_from_ip(request):
    """Get the location based on client IP."""
    ip = get_client_ip(request)
    if not ip or ip == '127.0.0.1':  # Handle localhost
        return 'Localhost'

    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        response.raise_for_status()
        data = response.json()
        city = data.get('city', 'Unknown Location')
        region = data.get('region', '')
        country = data.get('country', '')
        location = f"{city}, {region}, {country}".strip(", ")
    except requests.RequestException:
        location = 'Unknown Location'
    return location

def log_event(user, message):
    """Log an event for the user."""
    UserLog.objects.create(user=user, log_message=message)

def ice_button_pressed(user, button_name, location):
    """Log Ice Button pressed event."""
    message = f"The ICE Button ({button_name}) was pressed at {location}. Emergency protocols are now activated, and our team is taking immediate action to assist you."
    log_event(user, message)

def password_changed(user):
    """Log Password changed event."""
    message = "Your account password has been successfully updated. If this change wasn’t made by you, please contact our support team immediately."
    log_event(user, message)
    
def password_reset(user):
    """Log Password reset event."""
    message = "Your Password Reset was successful."
    log_event(user, message)

def email_verified(user, email_address):
    """Log Email verification success event."""
    message = f"Your email address ({email_address}) has been successfully verified. You will now receive important updates and notifications."
    log_event(user, message)

def sos_email_verified(user, contact_name, email_address):
    """Log SOS Email verification success event."""
    message = f"The SOS email address ({contact_name}: {email_address}) has been successfully verified. Emergency alerts will now be sent to this email when needed."
    log_event(user, message)

def sos_phone_verified(user, contact_name, phone_number):
    """Log SOS Phone verification success event."""
    message = f"The SOS phone number ({contact_name}: {phone_number}) has been successfully verified. Emergency alerts will now be sent to this number when necessary."
    log_event(user, message)

def login_activity_detected(user, device_name, location, date_time):
    """Log Login Activity Detected event."""
    message = f"A new login to your account was detected from {device_name} at {location} on {date_time}. If this wasn’t you, please secure your account immediately by changing your password and contacting support."
    log_event(user, message)

def subscription_transaction_successful(user, subscription_plan_name, transaction_amount, expiration_date):
    """Log Subscription Transaction Success event."""
    message = f"Your transaction for the {subscription_plan_name} subscription plan was successful. The amount of {transaction_amount} has been charged to your payment method. Your subscription is now active and valid until {expiration_date}."
    log_event(user, message)

def subscription_transaction_failed(user, subscription_plan_name):
    """Log Subscription Transaction Failed event."""
    message = f"Your transaction for the {subscription_plan_name} subscription plan was unsuccessful. Please verify your payment details or try again. If the issue persists, contact support for assistance."
    log_event(user, message)