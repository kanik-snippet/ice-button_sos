from core.models import Device
from rest_framework import serializers
from .models import BaseUser, PaymentHistory, Plan
from core.models import  *
from rest_framework.pagination import PageNumberPagination
from datetime import timedelta

   



class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaseUser
        fields = ['username', 'email', 'is_staff']  

    def create(self, validated_data):
        # Use the create_user method to ensure password is hashed
        user = BaseUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
        )
        user.is_staff = validated_data.get('is_staff', False)
        user.plan = validated_data.get('plan')  # Assign plan if applicable
        user.save()
        return user

class UserEditSerializer(serializers.ModelSerializer):
    country_code = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()

    class Meta:
        model = BaseUser
        fields = ['username', 'email', 'country_code', 'phone_number']

    def get_country_code(self, obj):
        """
        Extract the country code from the phone number.
        Assumes the phone number is stored in E.164 format (e.g., "+918430716493").
        """
        if obj.phone_number and obj.phone_number.startswith('+'):
            for i in range(1, len(obj.phone_number)):
                if not obj.phone_number[i].isdigit():
                    return obj.phone_number[:i]
                if len(obj.phone_number[:i]) > 3:
                    return obj.phone_number[:3]  # Default to common country code length
        return obj.phone_number[:3]  # Default to first 3 characters as a fallback

    def get_phone_number(self, obj):
        """
        Extract the phone number without the country code.
        """
        if obj.phone_number and obj.phone_number.startswith('+'):
            country_code_length = len(self.get_country_code(obj))
            return obj.phone_number[country_code_length:]
        return obj.phone_number


class PlanSerializer(serializers.ModelSerializer):
    stream_length_minutes = serializers.IntegerField(
        min_value=0, required=False, write_only=True, help_text="Stream length in minutes."
    )
    stream_length_seconds = serializers.IntegerField(
        min_value=0, required=False, write_only=True, help_text="Stream length in seconds."
    )

    class Meta:
        model = Plan
        fields = [
            'id', 'name', 'max_emails', 'max_phone_numbers', 'max_button', 'stream', 
            'cost', 'stream_length', 'stream_length_minutes', 'stream_length_seconds'
        ]
        extra_kwargs = {
            'name': {'help_text': 'Enter the name of the plan (max 50 characters).'},
            'max_emails': {'help_text': 'Maximum number of emails allowed.', 'min_value': 1},
            'max_phone_numbers': {'help_text': 'Maximum number of phone numbers allowed.', 'min_value': 1},
            'max_button': {'help_text': 'Maximum number of buttons allowed.', 'min_value': 1},
            'cost': {'help_text': 'Enter the cost for this plan (must be positive).', 'min_value': 0},
            'stream': {'help_text': 'Whether live streaming is enabled for this plan.'},
            'stream_length': {'read_only': True},  # Stream length is calculated from minutes and seconds
        }

    def validate_max_emails(self, value):
        if value <= 0:
            raise serializers.ValidationError("Max emails must be a positive number.")
        return value

    def validate_max_phone_numbers(self, value):
        if value <= 0:
            raise serializers.ValidationError("Max phone numbers must be a positive number.")
        return value

    def validate_max_button(self, value):
        if value <= 0:
            raise serializers.ValidationError("Max buttons must be a positive number.")
        return value

    def validate_cost(self, value):
        if value < 0:
            raise serializers.ValidationError("Cost must be a positive number.")
        return value

    def validate(self, attrs):
        """
        Custom validation for stream length fields.
        """
        minutes = attrs.pop('stream_length_minutes', 0)
        seconds = attrs.pop('stream_length_seconds', 0)

        if not (minutes or seconds):
            raise serializers.ValidationError("Either minutes or seconds for stream length must be provided.")

        try:
            attrs['stream_length'] = timedelta(minutes=int(minutes), seconds=int(seconds))
        except (ValueError, TypeError):
            raise serializers.ValidationError("Invalid values for stream length minutes or seconds.")

        return attrs



class DashboardStatsSerializer(serializers.Serializer):
    total_user = serializers.IntegerField()
    total_notifications = serializers.IntegerField()

class NotificationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationLog
        fields = ['id', 'call_type', 'message', 'created_at', 'device']

class FreeResultsSetPagination(PageNumberPagination):
    page_size = 20  # Set the number of items per page
    page_size_query_param = 'page_size'  # Allow the client to specify a page size
    max_page_size = 100  # Define the maximum page size

class UserSerializer(serializers.ModelSerializer):
    # Add any related fields or extra properties as needed
    plan_name = serializers.CharField(source='plan.name', read_only=True)  # Assuming you want to include the plan's name
    total_devices = serializers.SerializerMethodField()

    class Meta:
        model = BaseUser
        fields = [
            'uuid', 'username', 'first_name', 'last_name', 'email', 
            'is_verified', 'phone_number', 'plan_name', 'is_active', 
            'created_at', 'updated_at', 'total_devices'  # Include total_devices in the fields
        ]
        read_only_fields = ['uuid', 'email', 'created_at', 'updated_at']

    def get_total_devices(self, obj):
        """
        Returns the total number of devices associated with the user.
        """
        return Device.objects.filter(user=obj).count()




class DeviceSerializer(serializers.ModelSerializer):
    sos_emails = serializers.StringRelatedField(many=True)  # Assuming SOSEmails has a meaningful string representation
    sos_phones = serializers.StringRelatedField(many=True)  # Assuming SOSPhones has a meaningful string representation

    class Meta:
        model = Device
        fields = ['id','user','device_name','mac_address','message','description','device_status','sos_emails','sos_phones','created_at','updated_at',]
        read_only_fields = ['id', 'created_at', 'updated_at', 'user']


class UserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaseUser
        fields = ['username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser']

class PaymentHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentHistory
        fields = [
            'id', 'plan_name', 'amount', 'payment_status', 'payment_method',
            'currency', 'provider_order_id', 'payment_id', 'signature_id',
            'created_at', 'updated_at', 'processed_at'
        ]

class EventVideoSerializer(serializers.ModelSerializer):
    """
    Serializer for the video associated with an event.
    """
    class Meta:
        model = DeviceVideo
        fields = ['id', 'video', 'uploaded_at']

class EventSerializer(serializers.ModelSerializer):
    """
    Serializer for events with the associated video.
    """
    video = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ['event_id', 'user', 'device', 'created_at', 'video']

    def get_video(self, obj):
        # Get the video related to this event, if it exists
        video = DeviceVideo.objects.filter(event=obj).first()
        if video:
            return EventVideoSerializer(video).data
        return None

class AdminDeviceDetailsSerializer(serializers.ModelSerializer):
    user = UserDetailsSerializer(read_only=True)  # Nested user details

    class Meta:
        model = Device
        fields = ['device_name', 'mac_address','device_status', 'created_at', 'updated_at', 'user']