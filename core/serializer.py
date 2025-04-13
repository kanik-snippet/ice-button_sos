import os
import re
from django.conf import settings
from django.forms import ValidationError
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import *
from customadmin.models import PaymentHistory, Plan,FAQs,FAQHeading,StaticContent
from .utils import ice_button_pressed
from cloudinary.uploader import upload
from cloudinary.exceptions import Error as CloudinaryError 
class UserLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLog
        fields = ['id', 'user', 'log_message', 'created_at', 'read']
class StaticContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaticContent
        fields = ['id', 'title', 'slug', 'body', 'meta_title', 'meta_description']
class FAQsSerializer(serializers.ModelSerializer):
    # Rename the 'id' field to 'question_id' for the FAQs model
    question_id = serializers.IntegerField(source='id', read_only=True)

    class Meta:
        model = FAQs
        fields = ['question_id', 'question', 'answer', 'created_at', 'updated_at']

class FAQHeadingSerializer(serializers.ModelSerializer):
    faq_s = FAQsSerializer(many=True, read_only=True)  # Use related_name defined in the model

    # You can rename the 'id' field to 'title_id' for the FAQHeading model
    title_id = serializers.IntegerField(source='id', read_only=True)

    class Meta:
        model = FAQHeading
        fields = ['title_id', 'title', 'description', 'faq_s', 'created_at', 'updated_at']

class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = [
            'id',
            'name',                  
            'organization',         
            'email',                 
            'phone',                 
            'ice_quantity',          
            'installation_date',     
            'city',                  
            'subject',               
            'message',               
            'created_at',            
            'updated_at',            
        ]

class GetInTouchSerializer(serializers.ModelSerializer):
    country_code = serializers.CharField(max_length=5, required=False, allow_blank=True, write_only=True)  # Optional, write-only field

    class Meta:
        model = GetInTouch
        fields = ['id','name', 'email', 'country_code', 'phone_number', 'subject', 'message']
        read_only_fields = []  # No read-only fields in this context


    def validate_phone_number(self, value):
        """
        Ensure the phone number follows a valid format.
        """
        phone_regex = r'^\+?\d{9,15}$'  # Example regex for international phone numbers
        if not re.match(phone_regex, value):
            raise serializers.ValidationError("Invalid phone number format. Use '+1234567890' format.")
        return value

    def create(self, validated_data):
        """
        Override the `create` method to handle concatenating country code and phone number.
        """
        # Extract country_code and phone_number
        country_code = validated_data.pop('country_code', '').strip()  # Default to empty if not provided
        phone_number = validated_data.get('phone_number', '').strip()

        # Concatenate country code with phone number if country code exists
        if country_code and not phone_number.startswith('+'):
            validated_data['phone_number'] = f"{country_code}{phone_number}"
        elif not phone_number.startswith('+'):
            # Ensure phone number always starts with a '+' if no country code
            validated_data['phone_number'] = f"{phone_number}"

        return super().create(validated_data)

class RegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True, allow_null=True)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=20, required=False)
    country_code = serializers.CharField(max_length=10)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True) 
    
    def validate(self, data):
        # Validate that password and confirm_password match
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("The passwords you entered do not match. Please try again.")
        return data
    

class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(required=True, max_length=255, help_text="Username or email address")
    password = serializers.CharField(write_only=True, required=True, help_text="User password")


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class CustomSetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("The passwords you entered do not match. Please try again.")
        return data

    def save(self):
        user = self.context['user']
        user.set_password(self.validated_data['new_password'])
        user.save()


# DeviceRegisterSerializer
class DeviceRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['device_name', 'mac_address', 'message', 'description', 'device_status']

    def validate_mac_address(self, value):
        if not value:
            raise ValidationError('MAC address is required.')
        
        # Validate MAC address format
        mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_regex.match(value):
            raise ValidationError('Invalid MAC address format (e.g., XX:XX:XX:XX:XX:XX).')

        # Check if the MAC address is already registered
        if Device.objects.filter(mac_address=value).exists():
            raise ValidationError('This MAC address is already registered.')

        return value

    def create(self, validated_data):
        # Assign the current user as the device owner
        user = self.context['request'].user
        validated_data['user'] = user
        
        return Device.objects.create(**validated_data)





class DeviceUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['device_name', 'description']  # Limit fields to device_name and description
        extra_kwargs = {
            'device_name': {'required': True},  # Ensure device_name is always required
        }

    def update(self, instance, validated_data):
        # Update only device_name and description fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
class DeviceDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'device_name', 'mac_address','description', 'device_status', 'user', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'user']  # Fields that can't be modified by the user

    def validate_device_name(self, value):
        """Ensure the device name is not empty."""
        if not value:
            raise serializers.ValidationError("Device name cannot be empty.")
        return value

    def validate_mac_address(self, value):
        """Ensure the MAC address is in a valid format."""
        if len(value) != 17 or value.count(':') != 5:
            raise serializers.ValidationError("Invalid MAC address format.")
        return value

class EventSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.device_name', read_only=True)
    video_url = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ['id', 'device_name', 'event_id', 'created_at', 'video_url']

    def get_video_url(self, obj):
        # Assuming `related_name='devicevideo'` is set in the DeviceVideo model
        video = obj.devicevideo.first()
        if video and video.video:
            return video.video.url  # Extract the URL from the CloudinaryResource
        return None




class DeviceSerializer(serializers.ModelSerializer):
    phone_numbers = serializers.SerializerMethodField()
    RECIPIENT_EMAILS = serializers.SerializerMethodField()
    whatsapp_phone_numbers = serializers.SerializerMethodField()
    allowed_call_phone_numbers = serializers.SerializerMethodField()  # New field for allowed calls
    plan_details = serializers.SerializerMethodField()
    username = serializers.CharField(source='user.username', read_only=True)  # Include username
    description = serializers.CharField(read_only=True)  # Include description

    class Meta:
        model = Device
        fields = [
            'username', 'device_name', 'mac_address', 'message', 'description',
            'phone_numbers', 'device_status', 'RECIPIENT_EMAILS',
            'whatsapp_phone_numbers', 'allowed_call_phone_numbers', 'plan_details'  # Include new field
        ]

    def get_phone_numbers(self, obj):
        # Get only the phone numbers that are assigned to the device and verified, with country code
        phone_numbers = obj.sos_phones.filter(is_verified=True)  # Filtering verified phone numbers
        return [f"{phone.country_code}{phone.phone_numbers}" for phone in phone_numbers]

    def get_RECIPIENT_EMAILS(self, obj):
        # Get only the emails that are assigned to the device and verified
        emails = obj.sos_emails.filter(is_verified=True)  # Filtering verified emails
        return [email.emails for email in emails]

    def get_whatsapp_phone_numbers(self, obj):
        # Get only the phone numbers that are verified and allowed for WhatsApp, with country code
        whatsapp_phone_numbers = obj.sos_phones.filter(is_verified=True, allow_whatsapp=True)
        return [f"{phone.country_code}{phone.phone_numbers}" for phone in whatsapp_phone_numbers]

    def get_allowed_call_phone_numbers(self, obj):
        # Get only the phone numbers that are verified and allowed for calls, with country code
        allowed_call_phone_numbers = obj.sos_phones.filter(is_verified=True, allow_call=True)
        return [f"{phone.country_code}{phone.phone_numbers}" for phone in allowed_call_phone_numbers]

    def get_plan_details(self, obj):
        try:
            plan = obj.user.plan  # Assuming the user has a 'plan' field or method
            return {
                'name': plan.name,
                'max_emails': plan.max_emails,
                'max_phone_numbers': plan.max_phone_numbers,
                'max_button': plan.max_button,
                'stream': plan.stream,
                'stream_length': plan.stream_length.total_seconds()
            }
        except AttributeError:
            return None  

    def update(self, instance, validated_data):
        instance.device_name = validated_data.get('device_name', instance.device_name)
        instance.message = validated_data.get('message', instance.message)
        instance.device_status = validated_data.get('device_status', instance.device_status)
        instance.mac_address = validated_data.get('mac_address', instance.mac_address)
        instance.description = validated_data.get('description', instance.description)  # Update description
        instance.save()

        return instance




class DeviceVideoSerializer(serializers.ModelSerializer):
    mac_address = serializers.CharField(write_only=True)
    event_id = serializers.UUIDField(write_only=True)
    video = serializers.FileField(write_only=True)

    class Meta:
        model = DeviceVideo
        fields = ['event_id', 'mac_address', 'video']

    def validate(self, data):
        mac_address = data.get('mac_address')
        try:
            device = Device.objects.get(mac_address=mac_address)
            data['device'] = device
            data['user'] = device.user
        except Device.DoesNotExist:
            raise serializers.ValidationError(
                {"mac_address": "Device with this MAC address does not exist."}
            )
        return data

    def create(self, validated_data):
        validated_data.pop('mac_address', None)
        event_id = validated_data.pop('event_id')

        device = validated_data['device']
        user = validated_data['user']

        event, _ = Event.objects.get_or_create(
            event_id=event_id,
            defaults={'user': user, 'device': device}
        )
        validated_data['event'] = event

        # Save the instance and return it
        video_instance = super().create(validated_data)
        
        # After saving the video, we update the video_url field with the Cloudinary URL
        if video_instance.video_url:
            video_instance.set_video_url(video_instance.video_url)  # Save the Cloudinary URL
        return video_instance

      


class DeviceVideoListSerializer(serializers.ModelSerializer):
    event = EventSerializer()
    device = DeviceDetailSerializer()
    video_url = serializers.SerializerMethodField()

    class Meta:
        model = DeviceVideo
        fields = ['id', 'event', 'user', 'device', 'video_url', 'uploaded_at']

    def get_video_url(self, obj):
        # Ensure we return the URL of the video, not the Cloudinary resource object
        if obj.video_url:
            return obj.video_url  # This will return the actual URL as a string
        return None
    



class NotificationLogCreateSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.device_name', read_only=True)
    event_id = serializers.CharField(write_only=True)  # Accept `event_id` from the user but do not include in the output

    class Meta:
        model = NotificationLog
        fields = ['device_name', 'sent_to', 'mac_address', 'status', 'call_type', 'created_at', 'event_id']

    def create(self, validated_data):
        mac_address = validated_data.pop('mac_address')
        sent_to = validated_data.get('sent_to')
        status = validated_data.get('status')
        call_type = validated_data.get('call_type')
        event_id = validated_data.pop('event_id')  


        try:
            device = Device.objects.get(mac_address=mac_address)
        except Device.DoesNotExist:
            raise serializers.ValidationError("Device with this MAC address does not exist")

        event, created = Event.objects.get_or_create(
            event_id=event_id,
            defaults={'user': device.user, 'device': device}  
        )

        notification_log = NotificationLog.objects.create(
            event=event,
            device=device,
            mac_address=mac_address,
            sent_to=sent_to,
            status=status,
            call_type=call_type
        )

        return notification_log


class NotificationLogSerializer(serializers.ModelSerializer):
    """
    Serializer for NotificationLog model.
    """
    device = DeviceSerializer()  # Nested serializer to include device details in the log response

    class Meta:
        model = NotificationLog
        fields = ['id','event','device','mac_address','sent_to','status','call_type','created_at','updated_at']


class CombinedSOSSerializer(serializers.Serializer):
    """
    Serializer for SOS contacts with validation including country_code.
    """
    name = serializers.CharField(
        max_length=30,
        required=False,
        allow_blank=True,
        error_messages={"max_length": "Name cannot exceed 30 characters."}
    )
    relation = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        error_messages={"max_length": "Relation cannot exceed 20 characters."}
    )
    emails = serializers.EmailField(
        max_length=255,
        required=False,
        allow_blank=True,
        error_messages={
            "invalid": "Please provide a valid email address.",
            "max_length": "Email cannot exceed 255 characters."
        }
    )
    country_code = serializers.CharField(
        max_length=5,
        required=False,
        allow_blank=True,
        error_messages={
            "max_length": "Country code cannot exceed 5 characters.",
            "required": "Country code is required if a phone number is provided."
        }
    )
    phone_numbers = serializers.CharField(
        max_length=15,
        required=False,
        allow_blank=True,
        error_messages={
            "max_length": "Phone number cannot exceed 15 characters.",
            "required": "Phone number is required if country code is provided."
        }
    )
    allow_whatsapp = serializers.BooleanField(required=False, default=False)
    allow_sms = serializers.BooleanField(required=False, default=False)
    allow_call = serializers.BooleanField(required=False, default=False)

    def validate_phone_numbers(self, value):
        """
        Validate phone number contains only digits.
        """
        if value and not value.isdigit():
            raise serializers.ValidationError("Phone number must contain only numeric characters.")
        return value

    def validate_country_code(self, value):
        """
        Validate country code format.
        """
        if value and not value.startswith('+'):
            raise serializers.ValidationError("Country code must start with a '+' symbol.")
        return value

    def validate(self, data):
        """
        Global validation to ensure at least one contact method is provided.
        """
        email = data.get('emails')
        phone_number = data.get('phone_numbers')
        country_code = data.get('country_code')

        # Ensure at least one contact method is provided
        if not email and not phone_number:
            raise serializers.ValidationError(
                "At least one contact method (email or phone number) must be provided."
            )

        # If phone number is provided, ensure country code is also present
        if phone_number and not country_code:
            raise serializers.ValidationError(
                "A country code is required when a phone number is provided."
            )

        return data

class CombinedSOSWithCountryCodeSerializer(serializers.Serializer): 
    """
    Serializer for SOS contacts with country code validation.
    """
    name = serializers.CharField(
        max_length=30, 
        required=False, 
        allow_blank=True,
        error_messages={"max_length": "Name cannot exceed 30 characters."}
    )
    relation = serializers.CharField(
        max_length=20, 
        required=False, 
        allow_blank=True,
        error_messages={"max_length": "Relation cannot exceed 20 characters."}
    )
    emails = serializers.EmailField(
        max_length=255, 
        required=False, 
        allow_blank=True,
        error_messages={
            "invalid": "Please provide a valid email address.",
            "max_length": "Email cannot exceed 255 characters."
        }
    )
    country_code = serializers.CharField(
        max_length=5, 
        required=False, 
        allow_blank=True,
        error_messages={"max_length": "Country code cannot exceed 5 characters."}
    )
    phone_numbers = serializers.CharField(
        max_length=15, 
        required=False, 
        allow_blank=True,
        error_messages={
            "max_length": "Phone number cannot exceed 15 characters."
        }
    )
    allow_whatsapp = serializers.BooleanField(required=False, default=False)
    allow_sms = serializers.BooleanField(required=False, default=False)
    allow_call = serializers.BooleanField(required=False, default=False)

    def validate_emails(self, value):
        """
        Validate email address format.
        """
        if value and ('@' not in value or '.' not in value.split('@')[-1]):
            raise serializers.ValidationError("Please enter a valid email address.")
        return value

    def validate_country_code(self, value):
        """
        Validate country code format.
        """
        if value and not value.startswith('+'):
            raise serializers.ValidationError("Country code must start with a '+' symbol.")
        return value

    def validate(self, data):
        """
        Global validation for ensuring at least one contact method is provided.
        """
        email = data.get('emails')
        phone_number = data.get('phone_numbers')

        # Ensure at least one contact method is provided
        if not email and not phone_number:
            raise serializers.ValidationError(
                "At least one contact method (email or phone number) must be provided."
            )
        return data



class PlanSerializer(serializers.ModelSerializer):
    yearly_cost = serializers.SerializerMethodField()

    class Meta:
        model = Plan
        fields = ['id', 'name', 'max_emails', 'max_phone_numbers', 'max_button', 'subscription_type', 'cost', 'stream', 'stream_length', 'created_at', 'updated_at', 'yearly_cost']

    def get_yearly_cost(self, obj):
        return obj.get_yearly_cost() 

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for updating the user's profile and including plan details, 
    along with handling the profile image.
    """
    plan_details = PlanSerializer(source='plan', read_only=True)  # Use the PlanSerializer here
    total_sos_emails = serializers.SerializerMethodField()
    total_sos_phones = serializers.SerializerMethodField()
    profile_image = serializers.ImageField(required=False, allow_null=True)  # Add the profile image field

    class Meta:
        model = BaseUser
        fields = [
            'first_name', 'last_name', 'email', 'phone_number', 'username',
            'plan_details', 'total_sos_emails', 'total_sos_phones', 'profile_image'
        ]

    def validate_email(self, value):
        """
        Custom email validation to ensure uniqueness.
        """
        if BaseUser.objects.filter(email=value).exclude(id=self.instance.id).exists():
            raise serializers.ValidationError("This email is already taken.")
        return value

    def get_total_sos_emails(self, obj):
        """
        Get the total number of SOS emails associated with the user.
        """
        return obj.sos_emails.count()

    def get_total_sos_phones(self, obj):
        """
        Get the total number of SOS phones associated with the user.
        """
        return obj.sos_phones.count()

class ProfileImageUpdateSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=True)  # Make it required

    class Meta:
        model = BaseUser
        fields = ['profile_image']

    def update(self, instance, validated_data):
        """
        Replace the existing profile image with the new one if available.
        """
        # Check if the user already has a profile image and delete it if exists
        if instance.profile_image:
            instance.profile_image.delete()

        # Update the profile image with the new one
        instance.profile_image = validated_data.get('profile_image', instance.profile_image)
        
        # Save the instance after the update
        instance.save()
        return instance
    

    
class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for handling password change.
    """
    old_password = serializers.CharField(required=True, write_only=True)
    new_password1 = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        """
        Validate that the new passwords match and the old password is correct.
        """
        old_password = data.get('old_password')
        new_password1 = data.get('new_password1')
        new_password2 = data.get('new_password2')

        # Check if new passwords match
        if new_password1 != new_password2:
            raise serializers.ValidationError("New passwords do not match.")
        
        # Check if the old password is correct
        user = self.context.get('user')
        if not user.check_password(old_password):
            raise serializers.ValidationError("Old password is incorrect.")
        
        # Check if the new password is the same as the old password
        if old_password == new_password1:
            raise serializers.ValidationError("New password cannot be the same as the old password.")
        
        return data
    
class DeviceAssignContactsSerializer(serializers.Serializer):
    device_id = serializers.IntegerField()
    sos_emails = serializers.ListField(child=serializers.IntegerField(), required=False)
    sos_phones = serializers.ListField(child=serializers.IntegerField(), required=False)

    def validate_device_id(self, value):
        if not Device.objects.filter(id=value).exists():
            raise serializers.ValidationError("Device with this ID does not exist.")
        return value
    

class PaymentHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentHistory
        fields = '__all__'  # Or list specific fields you need
    

class SOSContactSerializer(serializers.Serializer):
    contact_type = serializers.CharField(read_only=True)
    contact_reference = serializers.UUIDField()
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(max_length=100, required=False)
    relation = serializers.CharField(max_length=50, required=False)
    emails = serializers.EmailField(max_length=255, required=False)
    country_code = serializers.CharField(max_length=5, required=False)
    phone_numbers = serializers.CharField(max_length=20, required=False)
    is_verified = serializers.BooleanField(default=False)
    allow_whatsapp = serializers.BooleanField(required=False, default=False)
    allow_sms = serializers.BooleanField(required=False, default=False)
    allow_call = serializers.BooleanField(required=False, default=False)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)

    def to_representation(self, instance):
        data = {}

        if isinstance(instance, SOSEmails):
            # Populate data for email contact
            data["contact_type"] = "email"
            data["email_id"] = instance.id
            data["contact_reference"] = instance.contact_reference
            data["emails"] = instance.emails
            data["name"] = instance.name
            data["relation"] = instance.relation
            data["email_verified"] = instance.is_verified
            data["created_at"] = instance.created_at.isoformat() if instance.created_at else None
            data["updated_at"] = instance.updated_at.isoformat() if instance.updated_at else None
        elif isinstance(instance, SOSPhones):
            # Populate data for phone contact
            data["contact_type"] = "phone"
            data["phone_id"] = instance.id
            data["contact_reference"] = instance.contact_reference
            data["country_code"] = instance.country_code
            data["phone_numbers"] = instance.phone_numbers
            data["name"] = instance.name
            data["relation"] = instance.relation
            data["phone_verified"] = instance.is_verified
            data["allow_whatsapp"] = instance.allow_whatsapp
            data["allow_sms"] = instance.allow_sms
            data["allow_call"] = instance.allow_call
            data["created_at"] = instance.created_at.isoformat() if instance.created_at else None
            data["updated_at"] = instance.updated_at.isoformat() if instance.updated_at else None

        return data
