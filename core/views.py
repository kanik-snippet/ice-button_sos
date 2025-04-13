# Free Library Imports
import logging
from datetime import timedelta
import os
import threading
import uuid
import logging
import subprocess
from cloudinary.uploader import upload
from cloudinary.exceptions import Error as CloudinaryError
# Third-party Library Imports
import requests
import razorpay
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse
from twilio.base.exceptions import TwilioRestException
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics,serializers
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError

# Django Imports
from django.shortcuts import get_object_or_404, render, redirect
from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from django.db.models import Q,Count
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.db import transaction
from django.core.cache import cache
from django.utils.timezone import now, localtime
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.decorators import method_decorator
from django.utils.encoding import force_str
from django.core.mail import EmailMultiAlternatives, send_mail
from django.template.loader import render_to_string
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import update_last_login
from .tokens import subscriber_token_generator
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext as _


# Local App Imports
from .utils import *
from core.models import Device,Event,DeviceVideo,SOSEmails,SOSPhones,GetInTouch,NotificationLog,DeviceStream
from customadmin.models import User, PaymentStatus, PaymentMethod,PaymentHistory,Plan,BaseUser,FAQHeading,StaticContent,Subscriber
from core.serializer import RegistrationSerializer,PlanSerializer,LoginSerializer,PasswordChangeSerializer,CombinedSOSSerializer,CombinedSOSWithCountryCodeSerializer,DeviceRegisterSerializer,SOSContactSerializer,DeviceDetailSerializer,EventSerializer,UserProfileSerializer,DeviceUpdateSerializer,NotificationLogCreateSerializer,NotificationLogSerializer,DeviceSerializer,DeviceVideoSerializer,DeviceVideoListSerializer,ContactUsSerializer,GetInTouchSerializer,FAQHeadingSerializer,StaticContentSerializer,PaymentHistorySerializer,UserLogSerializer,ProfileImageUpdateSerializer
# Create your views here.


# Define the view for the dashboard
def home(request):
    return render(request, 'auth/home.html', {'LANGUAGE_CODE': request.LANGUAGE_CODE})
def dashboard(request):
    return render(request, 'frontend/dash.html')

def remote(request):
    return render(request, 'frontend/remote.html')

def pod(request):
    return render(request, 'frontend/pod.html')

def log(request):
    return render(request, 'frontend/logs.html')

def live(request):
    return render(request, 'live.html')

def evlogs(request, event_id):
    # Just render the template and pass the event_id to it
    return render(request, 'frontend/evlogs.html', {'event_id': event_id})


def wifi(request):
    return render(request, 'frontend/wifi.html')
def stream(request):
    return render(request, 'frontend/stream.html')

def profile(request):
    return render(request, 'frontend/profile.html')

def change_password(request):
    return render(request, 'frontend/changepass.html')

def subscription(request):
    return render(request, 'frontend/subscription.html')
def subscription_txn(request):
    return render(request, 'frontend/subscription_txn.html')

def pod_detail(request, device_id):
    return render(request, 'frontend/pod_detail.html', {'device_id': device_id})

def login(request):
    return render(request,'auth/login.html')

def register(request):
    return render(request,'auth/register.html')

def forgot(request):
    return render(request,'auth/forgot.html')
def resetpass(request, token):
    # You can pass the token to the template if needed
    return render(request, 'auth/resetpass.html', {'token': token})
def static_content_view(request, slug):
    # Fetch the static content by slug
    content = get_object_or_404(StaticContent, slug=slug)
    return render(request, 'static_content.html', {'content': content})

# def email_content_view(request, slug):
#     # Fetch the static content by slug
#     content = get_object_or_404(emailContent, slug=slug)
#     return render(request, 'email_content.html', {'content': content})

def add_contact(request):
    return render(request, 'frontend/add_contact.html')
def terms(request):
    return render(request, 'terms-and-conditions.html')
def privacy(request):
    return render(request, 'Privacy.html')
def termsOfuse(request):
    return render(request, 'termsOfuse.html')
def salesandrefund(request):
    return render(request, 'salesandrefund.html')
def legalinfo(request):
    return render(request, 'legalinfo.html')
def test(request):
    return render(request, 'test.html')
def live(request, clean_mac):
    return render(request, 'frontend/live.html', {'clean_mac': clean_mac})

def ordernow(request):
    return render(request,'ordernow.html')
def tutorials(request):
    return render(request,'tutorials.html')
def plan_pricing(request):
    return render(request,'plan_pricing.html')
def case_study(request):
    return render(request,'case_study.html')
def hiworks(request):
    return render(request,'hiworks.html')
def user_invoice_view(request, transaction_id):
    transaction = get_object_or_404(PaymentHistory, pk=transaction_id)
    context = {
        'transaction': transaction
    }
    return render(request, 'invoice/user_invoice.html', context)

def notifications(request):
    return render(request, 'frontend/notifications.html')



# class SendMessageView(APIView):
#     authentication_classes = [JWTAuthentication]  # Use JWT Authentication
#     permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

#     def post(self, request, *args, **kwargs):
#         phone_number = request.data.get("phone")
#         message = request.data.get("message")

#         if not phone_number or not message:
#             return Response(
#                 {"error": "Phone number and message are required."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         try:
#             # Replace with actual logic for sending a WhatsApp message
#             response = send_whatsapp_message(phone_number, message)
#             return Response(
#                 {"response": f"Message sent to {phone_number}."},
#                 status=status.HTTP_200_OK,
#             )
#         except Exception as e:
#             return Response(
#                 {"error": f"Failed to send message: {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )

from django.template import Template, Context

from django.core.mail import EmailMultiAlternatives
from django.template import Template, Context
from django.conf import settings
from django.templatetags.static import static
from django.utils.html import strip_tags

def send_email(subject, template_name, context, to_email):
        """Helper method to send an email with both plain text and HTML content."""
        try:
            # Render the email content for both plain text and HTML
            plain_text_content = render_to_string(template_name, context)
            html_content = render_to_string(template_name, context)

            # Create an email message with both plain text and HTML content
            email = EmailMultiAlternatives(
                subject,
                plain_text_content,
                settings.DEFAULT_FROM_EMAIL,  # Sender's email address
                [to_email],  # Recipient's email address
            )
            email.attach_alternative(html_content, "text/html")  # Attach the HTML version
            email.send()
        except Exception as e:
            # Log the error or print it for debugging purposes
            print(f"Error sending email: {e}")

import logging

logger = logging.getLogger(__name__)
class SubscribeView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Subscribes a user by their email. Creates a new subscriber if the email does not exist.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email of the subscriber')
            },
        ),
        responses={
            200: openapi.Response("Successfully subscribed."),
            400: openapi.Response("Email is required."),
            409: openapi.Response("Already subscribed."),
        }
    )
    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"error": _("Email is required.")}, status=status.HTTP_400_BAD_REQUEST)

        subscriber, created = Subscriber.objects.get_or_create(email=email, defaults={'status': 'subscribed'})

        if not created and subscriber.status == 'subscribed':
            return Response({"message": _("Already subscribed.")}, status=status.HTTP_200_OK)

        if not created:
            subscriber.subscribe()

        # Log the name and unsubscribe URL
        name = subscriber.name or "Subscriber"
        unsubscribe_url = subscriber.generate_unsubscribe_url(request)
        subject = "ICE-BUTTON: Welcome to Our Newsletter!"
        template_name = "email/subscription_email.html"
        context = {"name": name, "unsubscribe_url": unsubscribe_url}
        send_email(subject, template_name, context, subscriber.email)

        return Response({"message": _("Successfully subscribed.")}, status=status.HTTP_200_OK)

        # Fetch the static content using slug
        # slug = "subscribe"  # For the subscription confirmation email
        # try:
        #     content = get_object_or_404(StaticContent, slug=slug)
        #     email_content = content.body  # Use the appropriate field containing the HTML/text
        # except StaticContent.DoesNotExist:
        #     email_content = "<p>Thank you for subscribing! Stay tuned for updates.</p>"

        # # Prepare the email subject and context
        # subject = "Welcome to Our Newsletter!"
        # context = {
        #     "name": name,
        #     "unsubscribe_url": unsubscribe_url,
        #     "email_content": email_content,  # Use the field content, not the object itself
        # }

        # # Send the email
        # send_email(subject, context, subscriber.email)

        # return Response({"message": "Successfully subscribed."}, status=status.HTTP_200_OK)

    

def unsubscribe(request, uidb64, token):
    """Handles unsubscribing a user based on the token."""
    try:
        # Decode the UID
        uid = urlsafe_base64_decode(uidb64).decode()
        subscriber = get_object_or_404(Subscriber, pk=uid)

        # Validate the token using the custom token generator
        if subscriber_token_generator.check_token(subscriber, token):  # Use custom token validation
            # Mark the subscriber as unsubscribed
            subscriber.unsubscribe()

            # Prepare the unsubscribe confirmation email content
            name = subscriber.name or "Subscriber"

            subject = "You have unsubscribed from our newsletter"
            template_name = "email/unsubscription_email.html"
            context = {
                "name": name
            }

            # Send the unsubscribe confirmation email
            send_email(subject, template_name, context, subscriber.email)

            return HttpResponse(_("You have successfully unsubscribed."), status=200)
        else:
            return HttpResponse("Invalid unsubscribe link.", status=400)
    except Exception as e:
        # Handle any exceptions, e.g., user not found
        return HttpResponse("Something went wrong. Please try again later.", status=400)

class PlanOverviewAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Retrieve all available plans along with the most purchased plan.",
        responses={
            200: openapi.Response(
                description="A list of plans and the most purchased plan.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "plans": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_OBJECT),
                            description="List of all available plans.",
                        ),
                        "most_purchased_plan": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "plan_name": openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description="The name of the most purchased plan.",
                                ),
                                "total_purchases": openapi.Schema(
                                    type=openapi.TYPE_INTEGER,
                                    description="The total number of purchases for the most purchased plan.",
                                ),
                            },
                            description="Details of the most purchased plan.",
                        ),
                    },
                ),
            ),
            401: openapi.Response(
                description="Unauthorized. The access token is missing or invalid."
            ),
            500: openapi.Response(description="Server error."),
        }
    )
    def get(self, request):
        try:
            # Fetch all plans
            plans = Plan.objects.all()
            serializer = PlanSerializer(plans, many=True)

            # Determine the most purchased plan based on PaymentHistory
            most_purchased_plan = (
                PaymentHistory.objects.filter(payment_status=PaymentStatus.SUCCEEDED.value)
                .values('plan_name')
                .annotate(total_purchases=Count('id'))
                .order_by('-total_purchases')
                .first()
            )

            if most_purchased_plan:
                most_purchased = {
                    "plan_name": most_purchased_plan['plan_name'],
                    "total_purchases": most_purchased_plan['total_purchases'],
                }
            else:
                most_purchased = None

            # Combine the plans and the most purchased plan in the response
            response_data = {
                "plans": serializer.data,
                "most_purchased_plan": most_purchased,
            }

            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def custom_404(request, exception):
    return render(request, '404.html', status=404)

bearer_token = openapi.Parameter(
        'Authorization', openapi.IN_HEADER, description="Bearer token",
        type=openapi.TYPE_STRING, required=True
    )
class UserRegistrationAPIView(APIView):
    """
    API View to register a new user.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Register a new user by providing username, email, password, etc.",
        request_body=RegistrationSerializer,
        responses={
            201: openapi.Response(description="Registration successfull"),
            400: openapi.Response(description="Bad request - Validation error"),
            500: openapi.Response(description="Server error")
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Handles user registration via POST request.
        """
        try:
            # Validate the incoming data using the RegistrationSerializer
            serializer = RegistrationSerializer(data=request.data)
            if serializer.is_valid():
                # Extract validated data
                validated_data = serializer.validated_data
                username = validated_data['username']
                first_name = validated_data['first_name']
                last_name = validated_data.get('last_name', '')
                email = validated_data['email']
                phone_number = validated_data.get('phone_number', '')
                country_code = validated_data['country_code']
                password = validated_data['password']

                # Check if email, phone number, or username already exists
                errors = {}
                if User.objects.filter(email=email).exists():
                    errors['email'] = [_("The email address you entered is already registered. Please use a different email.")]
                if User.objects.filter(phone_number=phone_number).exists():
                    errors['phone_number'] = [_("The phone number you entered is already registered. Please use a different phone number.")]
                if User.objects.filter(username=username).exists():
                    errors['username'] = [_("The username is already taken. Please choose a different username.")]
                
                if errors:
                    return Response({
                        "status": "error",
                        "message": "Registration failed",
                        "errors": errors
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Format full phone number
                full_phone_number = f"{country_code}{phone_number}" if phone_number else None

                # Set the default plan if no plan is provided
                selected_plan = get_object_or_404(Plan, name='Standard', subscription_type=Plan.MONTHLY)

                # Create a new user
                user = User(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    phone_number=full_phone_number,
                    plan=selected_plan,
                    is_verified=False  # User will verify via email
                )

                # Set the user's password
                user.set_password(password)
                user.save()

                # Send the email verification
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))
                verification_link = f"{settings.SITE_URL}/api/verify-email/{uid}/{token}/"
                # Render the registration verification email template
                message = render_to_string('email/email_verification.html', {
                    'user': user,
                    'verification_link': verification_link,
                })

                try:
                    email = EmailMultiAlternatives(
                        subject="Welcome to ICE-Button System – Verify Your Account",
                        body=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[user.email]
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except Exception as e:
                    return Response({'error': f'Failed to send verification email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # Return success response
                return Response({
                    'status': 'success',
                    'message': _("Registration successfull Please check your email to verify your account. Thank you for joining the ICE-Button System.")
                }, status=status.HTTP_201_CREATED)
            
            # If serializer is not valid, return the validation errors
            return Response({
                "status": "error",
                "message": _("Registration failed"),
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class VerifyEmailAPIView(APIView):
    """
    API to verify email using a token.
    """
    permission_classes = [AllowAny]  # No authentication required for verification

    def get(self, request, uidb64, token, *args, **kwargs):
        """
        Verifies the email based on the token provided.
        If valid, updates the email to verified and returns an HTML response.
        """
        try:
            # Decode the UID from the base64 URL
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_object_or_404(BaseUser, pk=uid)
        except (TypeError, ValueError, OverflowError):
            return self._generate_html_response(
               _("Verification Failed"), 
                "The verification link is invalid or expired. Please request a new verification link.", 
                400
            )
        
        # If the user is already verified, return an HTML response indicating so
        if user.is_verified:
            return self._generate_html_response(
                "Email Already Verified", 
                f"Your email {user.email} has already been verified. You can now proceed to log in.",
                200
            )

        # Check if the token is valid
        if default_token_generator.check_token(user, token):
            user.is_verified = True
            user.save()
            email_verified(user, user.email)

            # Return success response (HTML)
            return self._generate_html_response(
                "successfull", 
                f"{user.username}",
                200
            )
        
        # Return an HTML response for invalid token
        return self._generate_html_response(
            _("Failed"), 
            _("The verification link is invalid or expired. Please request a new verification link."), 
            400
        )

    def _generate_html_response(self, title, message, status_code):
        """
        Helper function to generate structured HTML responses for verification status.
        Renders the verification_response.html template with dynamic content.
        """
        # Render the HTML template with dynamic content
        html_content = render_to_string(
            'email/verification_status.html',  # Path to your HTML template
            {'verification_status': title, 'message': message, 'url':settings.SITE_URL}
        )
        return HttpResponse(html_content, content_type="text/html", status=status_code)


        
        
@method_decorator(csrf_exempt, name='dispatch')
class LoginAPIView(APIView):
    """
    API View for user login with JWT authentication.
    """
    permission_classes = [AllowAny]  # Make sure this view is accessible to all users

    @swagger_auto_schema(
        operation_description="Login with username/email and password to receive JWT tokens.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username_or_email': openapi.Schema(type=openapi.TYPE_STRING, description="Username or email of the user"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="Password of the user"),
            },
            required=['username_or_email', 'password'],
            example={
                "username_or_email": "test_user",
                "password": "example_password"
            }
        ),
        responses={
            200: openapi.Response(
                description="Login successfull, returns user data and JWT tokens",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'user': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'id': openapi.Schema(type=openapi.TYPE_STRING),
                                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                                        'full_name': openapi.Schema(type=openapi.TYPE_STRING),
                                        'is_superuser': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                        'is_staff': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                    }
                                ),
                                'tokens': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                                    }
                                ),
                            }
                        ),
                    }
                )
            ),
            400: openapi.Response(
                description="Bad Request (e.g., missing credentials or invalid user type)"
            ),
            401: openapi.Response(
                description="Unauthorized (e.g., invalid credentials or inactive account)"
            ),
        },
    )
    
    def post(self, request, *args, **kwargs):
        """
        Handle login via POST request. Upon successfull login, generate and return a JWT token.
        """
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "status": "error",
                "message": serializer.errors  # Send specific validation errors
            }, status=status.HTTP_400_BAD_REQUEST)

        username_or_email = serializer.validated_data['username_or_email']
        password = serializer.validated_data['password']

        # Authenticate the user based on username or email
        try:
            user = BaseUser.objects.get(Q(username=username_or_email) | Q(email=username_or_email))
        except BaseUser.DoesNotExist:
            return Response({
                "status": "error",
                "message": _("The user does not exist. Please register before logging in.")
            }, status=status.HTTP_401_UNAUTHORIZED)

        # If user is found, check the password
        if user and user.check_password(password):
            if user.is_active :
                update_last_login(None, user)
                # Get device name from user agent
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown Device')
                device_name = get_device_name(user_agent)
                location = get_location_from_ip(request)
                date_time = localtime().strftime('%Y-%m-%d %H:%M:%S')
                login_activity_detected(user, device_name, location, date_time)
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                # Prepare the user data to return
                user_data = {
                    "id": str(user.uuid),  # Return UUID as user ID
                    "email": user.email,
                    "full_name": f"{user.first_name} {user.last_name}",
                    "is_superuser": user.is_superuser,
                    "is_staff": user.is_staff,
                }

                # Return the formatted response
                return Response({
                    "status": "success",
                    "message": _("You have logged in successfully. Welcome back!"),
                    "data": {
                        "user": user_data,
                        "tokens": {
                            "access": access_token,
                            "refresh": str(refresh)
                        }
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status": "error",
                    "message": _("Your email address is not verified. Please verify your email to proceed.")
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                "status": "error",
                "message": _("The password you entered is incorrect. Please try again.")
            }, status=status.HTTP_401_UNAUTHORIZED)

class ChangePasswordAPIView(APIView):
    """
    API endpoint for changing the user's password.
    """
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    @swagger_auto_schema(
        operation_description="Change the password of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Password changed successfully.",
            ),
            400: openapi.Response(
                description="Bad Request. Invalid form data.",
            ),
            401: openapi.Response(
                description="Unauthorized. Access token is missing or invalid.",
            ),
        },
        request_body=PasswordChangeSerializer,  # Directly use the serializer for the request body
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}]  # This ensures the security is linked to the bearer token
    )
    def post(self, request):
        """
        Handle password change for the logged-in user.
        """
        # Initialize the serializer with the data and user context
        serializer = PasswordChangeSerializer(data=request.data, context={'user': request.user})

        if serializer.is_valid():
            new_password = serializer.validated_data['new_password1']
            request.user.set_password(new_password)
            request.user.save()
            password_changed(request.user)

            return Response({"detail": _("Your password was successfully updated!")}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestAPIView(APIView):
    """
    API to send password reset link to user email.
    """
    permission_classes = [AllowAny]  # Allows access without authentication

    @swagger_auto_schema(
        operation_description="Send password reset link to the user's email.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            }
        ),
        responses={
            200: openapi.Response(description='Password reset link sent successfully'),
            404: openapi.Response(description='User not found'),
        }
    )
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": _("Email field is required.")}, status=400)
        
        try:
            user = BaseUser.objects.get(email=email)
        except BaseUser.DoesNotExist:
            return Response({"error": _("We couldn’t find an account with the provided email. Please check and try again.")}, status=422)

        # Generate password reset token
        token = default_token_generator.make_token(user)

        # Generate password reset URL
        reset_url = reverse('resetpass', kwargs={'token': token})
        reset_link = f"{settings.SITE_URL}{reset_url}"

        # Render email template
        subject = 'ICE-Button System - Reset Your Password'
        message = render_to_string('email/password_reset_email.html', {
            'user': user,
            'reset_link': reset_link,
        })

        # Send the email
        email_message = EmailMultiAlternatives(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email]
        )
        email_message.attach_alternative(message, "text/html")
        email_message.send()

        return Response({"sucess": _("A password reset link has been sent to your registered email address. Please check your inbox and follow the instructions. Note: The reset link will expire in 5 minutes.")}, status=200)


class PasswordResetConfirmAPIView(APIView):
    """
    API to verify the password reset token.
    """
    permission_classes = [AllowAny]  # Allows access without authentication

    @swagger_auto_schema(
        operation_description="Verify the token sent to the user's email.",
        responses={
            200: openapi.Response(description='Token is valid, proceed to reset password.'),
            400: openapi.Response(description='Invalid token or expired link.'),
        }
    )
    def get(self, request, token):
        try:
            user = None
            for potential_user in BaseUser.objects.all():
                if default_token_generator.check_token(potential_user, token):
                    user = potential_user
                    break

            if user is None:
                return Response({"detail": "Invalid token or expired link."}, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                "detail": "Token is valid, proceed to reset password.",
                "token": token  # Return the token so the user can use it in the next step.
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetAPIView(APIView):
    permission_classes = [AllowAny]
    """
    API to reset the user's password after verifying the token.
    """

    @swagger_auto_schema(
        operation_description="Reset the user's password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, description='Confirm new password'),
            }
        ),
        responses={
            200: openapi.Response(description='Password has been reset successfully!'),
            400: openapi.Response(description='Invalid token or passwords do not match.'),
        }
    )
    def post(self, request, token):
        try:
            # Find user based on the token
            user = None
            for potential_user in BaseUser.objects.all():
                if default_token_generator.check_token(potential_user, token):
                    user = potential_user
                    break

            if user is None:
                raise ValidationError("Invalid token or expired link.")

            # Validate password match
            new_password = request.data.get('new_password')
            confirm_password = request.data.get('confirm_password')

            # Check if new password matches the old password
            if user.check_password(new_password):
                raise ValidationError(_("Your new password cannot be the same as your old password."))

            # Check if new password and confirm password match
            if new_password != confirm_password:
                raise ValidationError(_("The passwords you entered do not match. Please try again."))

            # Update the password
            user.password = make_password(new_password)
            user.save()
            password_reset(user)
            # Send the email
            subject = "ICE-Button System - Password Reset Confirmation"
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = user.email
            context = {"user_name": user.first_name or "User"}
            email_body = render_to_string("email/password_reset_confirmation.html", context)

            email = EmailMultiAlternatives(
                subject=subject,
                body=email_body,
                from_email=from_email,
                to=[to_email],
            )
            email.attach_alternative(email_body, "text/html")
            email.send()

            return Response({"detail": _("Your password has been reset successfully! You can now log in with your new password.")}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)





class CustomLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh_token")
            if refresh_token:
                # Blacklist the refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()
                print(f"Token {refresh_token} has been blacklisted.")  # Debugging log
            return Response({"message": _("You have logged out successfully. See you soon!")}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


def send_sos_verification_email(request,verification_url, sos_email):
    """Send an email to the user with a verification link."""

    subject = f'ICE-Button System {request.user.username} Has Added You as an SOS Contact in the ICE-Button System'
    message = render_to_string('email/sosemail_verification.html', {
        'user': request.user,
        'name': sos_email.name,
        'verification_link': verification_url,
    })

    recipient_email = sos_email.emails.strip()  

    email = EmailMultiAlternatives(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,  
        [recipient_email]    
    )
    email.attach_alternative(message, "text/html")  
    email.send()

class ResendVerificationEmailView(APIView):
    """
    API to resend a verification email for the specified SOS email contact.
    """
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this endpoint

    @swagger_auto_schema(
        operation_description="Resend a verification email for the specified SOS email contact.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email_id'],
            properties={
                'email_id': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="The ID of the SOS email contact."
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="Verification email successfully sent.",
                examples={
                    "application/json": {
                        "message": "A new verification email has been sent to example@email.com."
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid SOS email contact ID.",
                examples={
                    "application/json": {
                        "message": "Invalid SOS email contact ID."
                    }
                }
            ),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def post(self, request, *args, **kwargs):
        """
        Resend the SOS verification email to the specified email contact.
        """
        email_id = request.data.get('email_id')
        if not email_id:
            return Response({'message': _('Email ID is required.')}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the email contact for the authenticated user
            email_contact = get_object_or_404(SOSEmails, id=email_id, user=request.user)

            # Ensure the verification token exists, generate if missing
            if not email_contact.verification_token:
                token = str(uuid.uuid4())
                email_contact.verification_token = token
                email_contact.save()

            # Build the verification URL
            uid = urlsafe_base64_encode(str(email_contact.pk).encode('utf-8'))
            verification_url = f"{settings.SITE_URL}/api/verify-sos-email/{uid}/{email_contact.verification_token}/"

            # Send the verification email
            send_sos_verification_email(request, verification_url, email_contact)

            return Response(
                {'message': f'A new verification email has been sent to {email_contact.emails}.'},
                status=status.HTTP_200_OK
            )
        except SOSEmails.DoesNotExist:
            return Response(
                {'message': 'Invalid SOS email contact.'},
                status=status.HTTP_400_BAD_REQUEST
            )

class VerifySOSEmailView(APIView):
    """
    API to verify SOS email using a token.
    """
    permission_classes = [AllowAny]  # No authentication required for verification

    @swagger_auto_schema(
        operation_description="Verify the SOS email using the verification token.",
        responses={
            200: openapi.Response('HTML response for success'),
            400: openapi.Response('HTML response for failure'),
        },
    )

    def get(self, request, uidb64, token, *args, **kwargs):
        """
        Verifies the SOS email based on the token and UID provided.
        If valid, marks the email as verified and returns an HTML response.
        """
        try:
            # Decode UID and get the user object
            uid = force_str(urlsafe_base64_decode(uidb64))
            sos_email = SOSEmails.objects.get(pk=int(uid))

            # Check if the verification token matches
            if sos_email.verification_token != token:
                return self._generate_html_response(
                    _("Verification Failed"), 
                    _("The verification link is invalid or expired. Please request a new verification link."), 
                    400
                )

            # Mark the email as verified
            sos_email.is_verified = True
            sos_email.verification_token = None  # Invalidate the token after successfull verification
            sos_email.save()

            user = sos_email.user
            sos_email_verified(user, sos_email.name, sos_email.emails)

            # Return success response (HTML)
            return self._generate_html_response(
                "Verification successfull", 
                f"Thank you! The email {sos_email.emails} has been successfully verified.", 
                200
            )

        except (TypeError, ValueError, OverflowError, SOSEmails.DoesNotExist) as e:
            return self._generate_html_response(
                _("Verification Failed"), 
                _("The verification link is invalid or expired. Please request a new verification link."), 
                422
            )

    def _generate_html_response(self, title, message, status_code):
        """
        Helper function to generate structured HTML responses for verification status.
        """
        status = 'success' if status_code == 200 else 'failed'
        
        html_content = render_to_string(
            'email/verification_response.html',
            {
                'title': title,
                'message': message,
                'url': settings.SITE_URL,
                'status': status  # Pass status to template
            }
        )
        return HttpResponse(html_content, content_type="text/html", status=status_code)

  
 
def send_verification_sms(phone_number, verification_url, user_name,sos_name):
    try:
        # Ensure the username variable is used correctly in the message.
        message_body = (
            f"Hi {sos_name},\n\n"
            f"{user_name} added you as an SOS contact in the ICE-Button System. "
            f"Confirm via the link:\n"
            f"{verification_url}\n\n"
            f"Thank you for helping keep {user_name} safe.\n\n"
            f"Best Regards,\n"
            f"ICE-Button Team\n"
            f"support@ICE-Button.com | +91-9999525801"
        )

        # Create a Twilio client and send the message.
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=message_body,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        return {"success": True, "detail": _("Verification link sent successfully! Please check your SMS.")}

    except TwilioRestException as tre:
        if tre.code == 21408:
            error_message = f"Permission to send an SMS has not been enabled for the region indicated by the phone number {phone_number}."
        else:
            error_message = f"Twilio Error {tre.code}: {tre.msg}"
        return {"success": False, "detail": error_message}

    except Exception as e:
        error_message = f"Unexpected error occurred while sending SMS: {str(e)}"
        return {"success": False, "detail": error_message}
class VerifyPhoneAPIView(APIView):
    """
    API to verify a phone number using a token.
    """
    permission_classes = [AllowAny]  # No authentication required for verification

    @swagger_auto_schema(
        operation_description="Verify a phone number with a given token.",
        manual_parameters=[
            openapi.Parameter(
                'token', openapi.IN_PATH, description="Verification token for the phone number",
                type=openapi.TYPE_STRING, required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="Phone number verified successfully",
                examples={"application/json": {"detail": "Phone number verified successfully!"}}
            ),
            400: openapi.Response(
                description="Invalid or expired verification link",
                examples={"application/json": {"detail": "Verification link is invalid or has expired."}}
            )
        }
    )
    def get(self, request,uidb64, token):
        try:
            # Retrieve the SOSPhones instance with the given token
            uid = force_str(urlsafe_base64_decode(uidb64))
            sos_phone = SOSPhones.objects.get(pk=int(uid))

            if sos_phone.verification_token != token:
                return self._generate_html_response(
                    _("Verification Failed"), 
                    _("The verification link is invalid or expired. Please request a new verification link."), 
                    400
                )
            # Mark the phone number as verified
            sos_phone.is_verified = True
            sos_phone.verification_token = None  # Clear the token to prevent reuse
            sos_phone.save()
            user = sos_phone.user
            sos_phone_verified(user, sos_phone.name, sos_phone.phone_numbers)

            # Send WhatsApp link via Twilio
            try:
                full_phone_number = f"{sos_phone.country_code}{sos_phone.phone_numbers}"
                client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                message_body = (
                    f"Hi {sos_phone.name},\n\n"
                    f"{sos_phone.user.username} added you as an emergency contact in the ICE-Button System. "
                    f"Confirm to receive alerts via WhatsApp:\n"
                    f"{settings.TWILIO_WHATSAPP_LINK}\n\n"
                    f"Thank you for helping keep {sos_phone.user.username} safe.\n\n"
                    f"Best,\n"
                    f"ICE-Button Team\n"
                    f"support@ICE-Button.com | +91-9999525801"
                )

                client.messages.create(
                    body=message_body,
                    from_=settings.TWILIO_PHONE_NUMBER,
                    to=full_phone_number  # Use the phone number from the SOSPhones instance
                )
            except TwilioRestException as e:
                # If Twilio fails, return an HTML error message with the failure
                return self._generate_html_response(
                    _("Verification successfull"), 
                    f"Thank you! The phone number {full_phone_number} has been successfully verified. However, we were unable to send the WhatsApp link. Error: {str(e)}",
                    200
                )

            # Return an HTML response for success
            return self._generate_html_response(
                _("Phone Verification successfull"), 
                f"Thank you! The phone number {full_phone_number} has been successfully verified.",
                200
            )

        except SOSPhones.DoesNotExist:
            # Return an HTML response for failure when token does not exist
            return self._generate_html_response(
                _("Verification Failed"), 
                "The verification link is invalid or expired. Please request a new verification link.", 
                400
            )

        except Exception as e:
            # Return a generic failure HTML message
            return self._generate_html_response(
                _("Verification Failed"), 
                f"An unexpected error occurred: {str(e)}", 
                400
            )

    def _generate_html_response(self, title, message, status_code):
        """
        Helper function to generate structured HTML responses for verification status.
        Renders the verification_response.html template with dynamic content.
        """
        # Render the HTML template with dynamic content
        html_content = render_to_string(
            'email/verification_response.html',  # Path to your HTML template
            {'title': title, 'message': message,'url':settings.SITE_URL}
        )
        return HttpResponse(html_content, content_type="text/html", status=status_code)


    
class ResendVerificationSMSView(APIView):
    """
    API to send or resend verification SMS for a phone number if it's unverified.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Send or resend verification SMS for a phone number using its ID if it's unverified.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['phone_id'],
            properties={
                'phone_id': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="The ID of the SOS contact phone to verify."
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="Verification link sent successfully.",
                examples={"application/json": {"detail": "Verification link sent successfully! Please check your SMS."}}
            ),
            400: openapi.Response(
                description="Phone number is already verified or missing.",
                examples={"application/json": {"detail": "This phone number is already verified."}}
            ),
            404: openapi.Response(
                description="Phone number not found.",
                examples={"application/json": {"detail": "Phone ID not found."}}
            ),
            500: openapi.Response(
                description="Server error occurred while sending SMS.",
                examples={"application/json": {"detail": "Error sending verification SMS: <error_message>"}}
            ),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def post(self, request):
        phone_id = request.data.get("phone_id")
        
        if not phone_id:
            return Response({"detail": _("Phone ID is required.")}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the SOS contact phone record using the ID
            sos_phone = get_object_or_404(SOSPhones, id=phone_id, user=request.user)

            # Check if the phone number is already verified
            if sos_phone.is_verified:
                return Response({"detail": _("This phone number is already verified.")}, status=status.HTTP_400_BAD_REQUEST)

            # Generate or retrieve a verification token
            if not sos_phone.verification_token:
                token = str(uuid.uuid4())
                sos_phone.verification_token = token
                sos_phone.save()

            # Build the verification URL
            uid = urlsafe_base64_encode(str(sos_phone.pk).encode('utf-8'))
            verification_url = f"{settings.SITE_URL}/api/verify-phone/{uid}/{sos_phone.verification_token}/"
            full_phone_number = f"{sos_phone.country_code}{sos_phone.phone_numbers}"

            # Send verification SMS
            send_verification_sms(full_phone_number, verification_url, request.user.username, sos_phone.name)

            return Response({"detail": _("Verification link sent successfully! Please check your SMS.")}, status=status.HTTP_200_OK)

        except SOSPhones.DoesNotExist:
            return Response({"detail": _("Phone ID not found.")}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"detail": f"Error sending verification SMS: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AddSOSContactsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add SOS contacts (phone number or email) for the logged-in user.",
        request_body=CombinedSOSSerializer,
        responses={
            201: openapi.Response(
                description="Contact added successfully.",
            ),
            400: openapi.Response(
                description="Bad Request. Validation failed or maximum contacts limit reached.",
            ),
            401: "Unauthorized. Access token is missing or invalid.",
            404: openapi.Response(description="User not found."),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def post(self, request):
        print("Request received.")
        user_plan = request.user.plan
        max_emails = user_plan.max_emails
        max_phones = user_plan.max_phone_numbers
        print(f"User Plan: Max Emails = {max_emails}, Max Phones = {max_phones}")

        sos_emails = SOSEmails.objects.filter(user=request.user)
        sos_phones = SOSPhones.objects.filter(user=request.user)
        email_count = sos_emails.count()
        phone_count = sos_phones.count()
        print(f"Current SOS Contacts: Emails = {email_count}, Phones = {phone_count}")

        serializer = CombinedSOSSerializer(data=request.data)

        if not serializer.is_valid():
            print("Invalid data provided.")
            return Response(
                {"detail": "Invalid data provided.", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        email_address = serializer.validated_data.get("emails")
        phone_number = serializer.validated_data.get("phone_numbers")
        country_code = serializer.validated_data.get("country_code")
        name = serializer.validated_data["name"]
        relation = serializer.validated_data["relation"]
        allow_whatsapp = serializer.validated_data.get("allow_whatsapp", False)
        allow_sms = serializer.validated_data.get("allow_sms", False)
        allow_call = serializer.validated_data.get("allow_call", False)

        print(f"Validated Data: Name = {name}, Relation = {relation}, Email = {email_address}, Phone = {phone_number}")

        errors = []

        with transaction.atomic():
            contact_reference = uuid.uuid4()
            existing_email = sos_emails.filter(name=name, relation=relation).first()
            existing_phone = sos_phones.filter(name=name, relation=relation).first()
            if existing_email:
                contact_reference = existing_email.contact_reference
            elif existing_phone:
                contact_reference = existing_phone.contact_reference
            print(f"Generated Contact Reference: {contact_reference}")

            if email_address:
                if email_count >= max_emails:
                    errors.append(f"Max email limit reached ({max_emails}).")
                elif sos_emails.filter(emails=email_address).exists():
                    errors.append(f"Email '{email_address}' already exists.")
                else:
                    try:
                        print("Saving email contact...")
                        sos_email = SOSEmails(
                            user=request.user,
                            contact_reference=contact_reference,
                            emails=email_address,
                            name=name,
                            relation=relation,
                            is_verified=False,
                        )
                        sos_email.verification_token = str(uuid.uuid4())
                        sos_email.save()
                        uid = urlsafe_base64_encode(str(sos_email.pk).encode('utf-8'))
                        verification_url = f"{settings.SITE_URL}/api/verify-sos-email/{uid}/{sos_email.verification_token}/"
                        print(f"Sending verification email to {email_address}...")
                        send_sos_verification_email(request, verification_url, sos_email)
                    except Exception as e:
                        errors.append(f"Failed to add email '{email_address}': {str(e)}")

            if phone_number:
                if phone_count >= max_phones:
                    errors.append(f"Max phone limit reached ({max_phones}).")
                elif sos_phones.filter(phone_numbers=phone_number).exists():
                    errors.append(f"Phone '{phone_number}' already exists.")
                else:
                    try:
                        print("Saving phone contact...")
                        sos_phone = SOSPhones(
                            user=request.user,
                            contact_reference=contact_reference,
                            phone_numbers=phone_number,
                            country_code=country_code,
                            name=name,
                            relation=relation,
                            allow_whatsapp=allow_whatsapp,
                            allow_sms=allow_sms,
                            allow_call=allow_call,
                            is_verified=False,
                        )
                        sos_phone.verification_token = str(uuid.uuid4())
                        sos_phone.save()
                        uid = urlsafe_base64_encode(str(sos_phone.pk).encode('utf-8'))
                        verification_url = f"{settings.SITE_URL}/api/verify-phone/{uid}/{sos_phone.verification_token}/"
                        print(f"Sending verification SMS to {country_code}{phone_number}...")
                        send_verification_sms(f"{country_code}{phone_number}", verification_url, request.user.username, name)
                    except Exception as e:
                        errors.append(f"Failed to add phone '{phone_number}': {str(e)}")

        email_display = email_address if email_address else "N/A"
        phone_display = phone_number if phone_number else "N/A"

        if errors:
            print("Errors encountered:", errors)
            return Response(
                {"errors": errors}, status=status.HTTP_400_BAD_REQUEST
            )

        print("SOS contact added successfully!")
        return Response(
            {
                "success": [
                    f"The SOS contact has been added successfully! Verification required for email ({email_display}) and phone ({phone_display}). "
                    f"Verification link expires in 5 minutes."
                ]
            },
            status=status.HTTP_201_CREATED,
        )
    

class UpdateSOSContactsView(APIView):
    """
    API to update SOS contacts for the logged-in user.
    Allows modifying contact details (name, relation, email, phone number, and permissions).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update an SOS contact for the logged-in user.",
        request_body=CombinedSOSWithCountryCodeSerializer,
        responses={
            200: openapi.Response(
                description="Contact updated successfully.",
                schema=CombinedSOSWithCountryCodeSerializer,
            ),
            400: openapi.Response(
                description="Bad Request. Validation failed or invalid data provided.",
            ),
            401: "Unauthorized. Access token is missing or invalid.",
            404: openapi.Response(description="Contact not found."),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def put(self, request, contact_reference):
        """
        Handle PUT request to update SOS contacts.
        """
        with transaction.atomic():
            # Fetch the existing contact for the user, either email or phone
            try:
                sos_email = SOSEmails.objects.get(user=request.user, contact_reference=contact_reference)
            except SOSEmails.DoesNotExist:
                sos_email = None

            try:
                sos_phone = SOSPhones.objects.get(user=request.user, contact_reference=contact_reference)
            except SOSPhones.DoesNotExist:
                sos_phone = None

            # Ensure at least one contact exists
            if not sos_email and not sos_phone:
                return Response(
                    {"detail": "Contact not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Validate input data using the serializer
            serializer = CombinedSOSWithCountryCodeSerializer(data=request.data)
            if serializer.is_valid():
                name = serializer.validated_data.get('name')
                relation = serializer.validated_data.get('relation')
                emails = serializer.validated_data.get('emails')
                phone_numbers = serializer.validated_data.get('phone_numbers')
                country_code = serializer.validated_data.get('country_code')
                allow_whatsapp = serializer.validated_data.get('allow_whatsapp', False)
                allow_sms = serializer.validated_data.get('allow_sms', False)
                allow_call = serializer.validated_data.get('allow_call', False)

                # Update or create phone contact
                if phone_numbers:
                    if not sos_phone:
                        sos_phone = SOSPhones.objects.create(
                            user=request.user,
                            contact_reference=contact_reference,
                            name=name,
                            relation=relation,
                            phone_numbers=phone_numbers,
                            country_code=country_code,
                            allow_whatsapp=allow_whatsapp,
                            allow_sms=allow_sms,
                            allow_call=allow_call,
                        )
                    else:
                        sos_phone.name = name or sos_phone.name
                        sos_phone.relation = relation or sos_phone.relation
                        sos_phone.phone_numbers = phone_numbers
                        sos_phone.country_code = country_code or sos_phone.country_code
                        sos_phone.allow_whatsapp = allow_whatsapp
                        sos_phone.allow_sms = allow_sms
                        sos_phone.allow_call = allow_call
                        sos_phone.save()

                # Update or create email contact
                if emails:
                    if not sos_email:
                        sos_email = SOSEmails.objects.create(
                            user=request.user,
                            contact_reference=contact_reference,
                            name=name,
                            relation=relation,
                            emails=emails,
                        )
                    else:
                        sos_email.name = name or sos_email.name
                        sos_email.relation = relation or sos_email.relation
                        sos_email.emails = emails
                        sos_email.save()

                return Response({"detail": _("SOS contact updated successfully.")}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class DeleteSOSContactView(APIView):
    """
    API to delete SOS contacts (email or phone number) for the logged-in user.
    Allows deleting both a phone number and email from the user's SOS contacts list.
    """
    authentication_classes = [JWTAuthentication]  # Add your authentication classes if needed
    permission_classes = [IsAuthenticated] 

    # Swagger Documentation
    @swagger_auto_schema(
        operation_description="Delete SOS contacts (email and/or phone number) for the logged-in user.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="Email ID address to delete"),
                'phone_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="Phone ID number to delete"),
            },
            required=['emails', 'phone_numbers']
        ),
        responses={
            204: openapi.Response(description="Contact(s) deleted successfully."),
            400: openapi.Response(description="Bad Request. Validation failed or invalid data provided."),
            401: "Unauthorized. Access token is missing or invalid.",
            404: openapi.Response(description="Contact(s) not found."),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )

    def delete(self, request):
        """
        Handle DELETE request to remove SOS contacts using email_id and/or phone_id.
        """
        email_id = request.data.get('email_id')
        phone_id = request.data.get('phone_id')

        # Validate that at least one identifier (email_id or phone_id) is provided
        if not email_id and not phone_id:
            return Response({"detail": _("Please provide either an email_id or phone_id to delete.")}, status=status.HTTP_400_BAD_REQUEST)

        responses = []

        # Handle email contact deletion
        if email_id:
            try:
                sos_email = SOSEmails.objects.get(user=request.user, id=email_id)
                email_address = sos_email.emails
                sos_email.delete()

                # Send email notification
                self.send_email_notification(
                    email=email_address,
                    user_name=request.user.username
                )

                responses.append({"detail": f"SOS email contact {email_address} deleted successfully!"})
            except SOSEmails.DoesNotExist:
                responses.append({"detail": f"Email contact with ID {email_id} not found."})

        # Handle phone number contact deletion
        if phone_id:
            try:
                # Fetch the SOS phone contact by ID
                sos_phone = SOSPhones.objects.get(user=request.user, id=phone_id)
                
                # Combine country code and phone number to get the full phone number
                country_code = sos_phone.country_code if sos_phone.country_code else ""  # Use an empty string if country_code is None
                full_phone_number = f"{country_code}{sos_phone.phone_numbers}"  # Concatenate country code with phone number

                # Delete the SOS phone contact
                sos_phone.delete()

                # Send SMS notification with the full phone number (including country code)
                self.send_sms_notification(
                    phone_number=full_phone_number,
                    user_name=request.user.username
                )

                responses.append({"detail": f"SOS phone contact {full_phone_number} deleted successfully!"})
            except SOSPhones.DoesNotExist:
                responses.append({"detail": f"Phone contact with ID {phone_id} not found."})

        # If there are responses (both success and failure messages), return them
        if responses:
            return Response(responses, status=status.HTTP_204_NO_CONTENT)

        # If no contacts found to delete
        return Response({"detail": "Invalid contact information provided."}, status=status.HTTP_400_BAD_REQUEST)

    def send_email_notification(self, email, user_name):
        """
        Send an email notification to the deleted email contact.
        """
        try:
            subject = "Your SOS Contact has been removed"
            message = (
                f"Hi,\n\n"
                f"This is to notify you that you have been removed as an SOS contact for {user_name} in the ICE-Button System.\n\n"
                f"If you have any questions, please contact {user_name} directly.\n\n"
                f"Best Regards,\n"
                f"The ICE-Button Team\n"
                f"support@ICE-Button.com | +91-9999525801"
            )

            # Send email
            email = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[email]
            )
            email.send()
        except Exception as e:
            print(f"Error sending email notification: {str(e)}")

    def send_sms_notification(self, phone_number, user_name):
        """
        Send an SMS notification to the deleted phone contact.
        """
        try:
            message_body = (
                f"Hi,\n\n"
                f"This is to notify you that you have been removed as an SOS contact for {user_name} in the ICE-Button System.\n\n"
                f"Best Regards,\n"
                f"The ICE-Button Team"
            )

            # Send SMS
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            client.messages.create(
                body=message_body,
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )
        except Exception as e:
            print(f"Error sending SMS notification: {str(e)}")

class SOSContactListView(APIView):
    """
    Fetch all SOS contacts in a unified format.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Fetch all SOS contacts (emails and phone numbers) for the logged-in user in a unified format.",
        responses={
            200: openapi.Response(
                description="List of SOS contacts",
                examples={
                    "application/json": {
                        "sos_contacts": [
                            {
                                "contact_reference": "uuid-string",
                                "contact_type": "email",
                                "emails": "example@example.com",
                                "phone_numbers": None,
                                "email_verified": True,
                                "name": "John Doe",
                                "relation": "Friend",
                            },
                            {
                                "contact_reference": "uuid-string",
                                "contact_type": "phone",
                                "emails": None,
                                "phone_numbers": "+123456789",
                                "phone_verified": False,
                                "name": "Jane Doe",
                                "relation": "Sister",
                            }
                        ]
                    }
                }
            ),
            401: openapi.Response(
                description="Unauthorized. User is not authenticated."
            ),
        },
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                in_=openapi.IN_HEADER,
                description="Bearer Token for authentication",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        security=[{"Bearer": []}],
    )
    def get(self, request, *args, **kwargs):
        # Fetch SOS contacts (emails and phones) for the user
        email_contacts = SOSEmails.objects.filter(user=request.user)
        phone_contacts = SOSPhones.objects.filter(user=request.user)

        # Combine email and phone contacts into a single list
        combined_contacts = list(email_contacts) + list(phone_contacts)

        # Remove duplicates based on 'name' and 'relation' pairs
        unique_contacts = {}
        for contact in combined_contacts:
            # Generate unique key based on 'name' and 'relation' to avoid duplicates
            key = f"{contact.name}-{contact.relation}"
            if key not in unique_contacts:
                unique_contacts[key] = contact

        # Calculate the total number of unique contacts
        total_soscontacts = len(unique_contacts)

        # Serialize contacts
        serializer = SOSContactSerializer(combined_contacts, many=True)

        # Return grouped response with the total count of unique contacts
        return Response({
            "sos_contacts": serializer.data,
            "total_soscontacts": total_soscontacts,  # Send total number of unique contacts
        }, status=200)

    

class AssignContactToDeviceAPIView(APIView):
    """
    API endpoint to assign an SOS email or SOS phone contact to a device.
    The contact IDs (email ID or phone ID) are required for faster filtering.
    """
    
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this endpoint

    @swagger_auto_schema(
        operation_description="Assign either an SOS email or SOS phone contact to a device. Email ID or phone ID is required.",
        responses={
            200: openapi.Response(
                description="Contact assigned successfully",
                examples={
                    'application/json': {
                        'status': 'success',
                        'message': "SOS email contact with ID '1' assigned to the device successfully."
                    }
                }
            ),
            400: openapi.Response(
                description="Bad Request - Missing or invalid parameters",
                examples={
                    'application/json': {
                        'error': "Device ID and at least one contact ID (email ID or phone ID) are required."
                    }
                }
            ),
            404: openapi.Response(
                description="Not Found - Device or Contact not found",
                examples={
                    'application/json': {
                        'error': "Device or Contact not found."
                    }
                }
            ),
        },
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['device_id'],
            properties={
                'device_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the device to which contact is to be assigned'),
                'email_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='SOS email contact ID (optional)'),
                'phone_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='SOS phone contact ID (optional)')
            }
        )
    )
    def post(self, request):
        device_id = request.data.get('device_id')
        email_id = request.data.get('email_id')  # SOS email contact ID
        phone_id = request.data.get('phone_id')  # SOS phone contact ID

        # Validate the incoming data
        if not device_id:
            return Response({"error": _("Device ID is required.")}, status=status.HTTP_400_BAD_REQUEST)
        if not email_id and not phone_id:
            return Response({"error": _("At least one contact (email or phone) must be provided.")}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the device with related contacts
        try:
            device = Device.objects.prefetch_related('sos_emails', 'sos_phones').get(id=device_id, user=request.user)
        except Device.DoesNotExist:
            return Response({"error": _("Device not found or access denied.")}, status=status.HTTP_404_NOT_FOUND)

        # Initialize messages
        message_parts = []

        # Handle email contact
        if email_id:
            email_contact = SOSEmails.objects.filter(id=email_id, user=request.user).first()
            if not email_contact:
                return Response({"error": f"SOS email is not available or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
            if not device.sos_emails.filter(id=email_contact.id).exists():
                device.sos_emails.add(email_contact)
                message_parts.append(f"SOS email contact is assigned to the device.")
            else:
                message_parts.append(f"SOS email contact is already assigned to the device.")

        # Handle phone contact
        if phone_id:
            phone_contact = SOSPhones.objects.filter(id=phone_id, user=request.user).first()
            if not phone_contact:
                return Response({"error": f"SOS phone is not available or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
            if not device.sos_phones.filter(id=phone_contact.id).exists():
                device.sos_phones.add(phone_contact)
                message_parts.append(f"SOS phone contact is assigned to the device.")
            else:
                message_parts.append(f"SOS phone contact is already assigned to the device.")

        # Combine messages and return response
        message = " ".join(message_parts) if message_parts else "No SOS contacts assigned."
        return Response({"status": "success", "message": message}, status=status.HTTP_200_OK)

class RemoveContactFromDeviceAPIView(APIView):
    """
    API endpoint to remove a single SOS email or SOS phone contact from a device.
    """

    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this endpoint
    
    @swagger_auto_schema(
        operation_description="Remove either an SOS email or SOS phone contact from a device.",
        responses={
            200: openapi.Response(  
                description="Contact removed successfully",
                examples={
                    'application/json': {
                        'status': 'success',
                        'message': "SOS email contact 'email@example.com' and phone contact '1234567890' removed from the device successfully."
                    }
                }
            ),
            400: openapi.Response(
                description="Bad Request - Missing or invalid parameters",
                examples={
                    'application/json': {
                        'error': "Device ID is required."
                    }
                }
            ),
            404: openapi.Response(
                description="Not Found - Device or Contact not found",
                examples={
                    'application/json': {
                        'error': "Device or contact not found."
                    }
                }
            ),
            409: openapi.Response(
                description="Conflict - Contact not assigned to the device",
                examples={
                    'application/json': {
                        'error': "SOS email contact 'email@example.com' or phone contact '1234567890' is not assigned to the device."
                    }
                }
            ),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['device_id'],
            properties={
                'device_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the device from which contact is to be removed'),
                'email_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the SOS email contact (optional)'),
                'phone_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the SOS phone contact (optional)')
            }
        )
    )
    def post(self, request):
        device_id = request.data.get('device_id')
        email_id = request.data.get('email_id')  # Single email contact ID
        phone_id = request.data.get('phone_id')  # Single phone contact ID

        # Validate the incoming data
        if not device_id:
            return Response({"error": "Device ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Fetch the device
        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            return Response({"error": "Device not found."}, status=status.HTTP_404_NOT_FOUND)
        
        # Initialize message
        message_parts = []
        not_found = []

        # Process email contact if provided
        if email_id:
            try:
                email_contact = SOSEmails.objects.get(id=email_id)
                
                # Check if email contact is assigned
                if email_contact in device.sos_emails.all():
                    # Remove email contact if assigned
                    device.sos_emails.remove(email_contact)
                    message_parts.append(f"SOS email contact '{email_contact.emails}' removed from the device.")
                else:
                    not_found.append(f"SOS email contact '{email_contact.emails}' is not assigned to the device.")
            except SOSEmails.DoesNotExist:
                return Response({
                    'error': f"SOS email with ID {email_id} not available."
                }, status=status.HTTP_404_NOT_FOUND)

        # Process phone contact if provided
        if phone_id:
            try:
                phone_contact = SOSPhones.objects.get(id=phone_id)
                
                # Check if phone contact is assigned
                if phone_contact in device.sos_phones.all():
                    # Remove phone contact if assigned
                    device.sos_phones.remove(phone_contact)
                    message_parts.append(f"SOS phone contact '{phone_contact.phone_numbers}' removed from the device.")
                else:
                    not_found.append(f"SOS phone contact '{phone_contact.phone_numbers}' is not assigned to the device.")
            except SOSPhones.DoesNotExist:
                return Response({
                    'error': f"SOS phone with ID {phone_id} not available."
                }, status=status.HTTP_404_NOT_FOUND)

        # If no assigned contacts found, return a 409 Conflict error
        if not_found:
            return Response({
                'error': ' and '.join(not_found)  # Concatenate not found messages
            }, status=status.HTTP_409_CONFLICT)

        # Combine the messages for removed email and phone contacts
        if not message_parts:
            message = "No SOS contacts removed."
        else:
            message = ' and '.join(message_parts) + " successfully."

        # Return success message
        return Response({
            'status': 'success',
            'message': message
        }, status=status.HTTP_200_OK)


# class DeleteSOSEmailAPIView(APIView):
#     """
#     API view to delete an SOS email contact and send a notification email.
#     """
#     permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

#     @swagger_auto_schema(
#         operation_description="Delete an SOS email contact by ID and send a notification email",
#         responses={
#             200: openapi.Response(
#                 description="Email deleted successfully and notification sent",
#                 examples={"application/json": {"status": "success", "message": "Email deleted successfully and notification sent."}},
#             ),
#             404: openapi.Response(
#                 description="SOS email not found",
#                 examples={"application/json": {"status": "error", "message": "SOS email not found."}},
#             ),
#         },
#         manual_parameters=[bearer_token],
#         security=[{'Bearer': []}],
#     )
#     def delete(self, request, SOSEmails_id):
#         # Retrieve the SOS email contact
#         email = get_object_or_404(SOSEmails, id=SOSEmails_id, user=request.user)
#         user_email = email.emails
#         user_name = email.user.username
        
#         # Delete the email from the database
#         email.delete()

#         # Prepare and send the notification email
#         email_message = (
#             f"Dear User,\n\n"
#             f"The email, {user_email}, has been successfully removed from the ICE-Button System for user {user_name}. "
#             f"If this was done in error or you need assistance, please contact our support team.\n\n"
#             f"Best regards,\nThe ICE-Button Team"
#         )

#         send_mail(
#             subject='Email Removed from ICE-Button System',
#             message=email_message,
#             from_email=settings.DEFAULT_FROM_EMAIL,
#             recipient_list=[user_email],
#             fail_silently=False,
#         )

#         # Respond with success message
#         return Response(
#             {
#                 "status": "success",
#                 "message": "Email deleted successfully and notification sent."
#             },
#             status=status.HTTP_200_OK
#         )

# class DeleteSOSPhoneAPIView(APIView):
#     """
#     API view to delete an SOS phone contact and send a Twilio SMS notification.
#     """
#     permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

#     @swagger_auto_schema(
#         operation_description="Delete an SOS phone contact by ID and send SMS notification",
#         responses={
#             200: openapi.Response(
#                 description="Phone number deleted successfully and notification sent",
#                 examples={"application/json": {"status": "success", "message": "Phone number deleted successfully and notification sent."}},
#             ),
#             404: openapi.Response(
#                 description="SOS phone number not found",
#                 examples={"application/json": {"status": "error", "message": "SOS phone number not found."}},
#             ),
#         },
#         manual_parameters=[bearer_token],
#         security=[{'Bearer': []}],
#     )
#     def delete(self, request, SOSPhones_id):
#         # Retrieve the SOS phone contact
#         phone_number = get_object_or_404(SOSPhones, id=SOSPhones_id, user=request.user)
#         user_phone = phone_number.phone_numbers
        
#         # Delete the phone number from the database
#         phone_number.delete()

#         # Send SMS notification via Twilio
#         client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
#         sms_message = (
#             f"The phone number {user_phone} has been successfully removed from the ICE-Button System. If this was not authorized, please contact support immediately.\n"
#             f"Best regards,\nMobiloitte"
#         )
        
#         client.messages.create(
#             body=sms_message,
#             from_=settings.TWILIO_PHONE_NUMBER,
#             to=user_phone
#         )

#         # Respond with success message
#         return Response(
#             {
#                 "status": "success",
#                 "message": "Phone number deleted successfully and notification sent."
#             },
#             status=status.HTTP_200_OK
#         )


class DashboardAPIView(APIView):
    authentication_classes = [SessionAuthentication, JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve dashboard data for the logged-in user, including device count, notifications, and SOS contacts.",
        responses={
            200: openapi.Response(
                description="Dashboard data retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'total_devices': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of devices associated with the user"),
                        'total_notifications': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of notifications for the user's devices"),
                        'total_soscontacts': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of SOS contacts"),
                        'devices': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'id': openapi.Schema(type=openapi.TYPE_STRING, description="Device ID"),
                                    'device_name': openapi.Schema(type=openapi.TYPE_STRING, description="Device name"),
                                    'mac_address': openapi.Schema(type=openapi.TYPE_STRING, description="MAC address of the device"),
                                    'description': openapi.Schema(type=openapi.TYPE_STRING, description="Description of the device"),
                                    'device_status': openapi.Schema(type=openapi.TYPE_STRING, description="Device status"),
                                    'created_at': openapi.Schema(type=openapi.FORMAT_DATETIME, description="Device creation date"),
                                    'contacts': openapi.Schema(
                                        type=openapi.TYPE_ARRAY,
                                        items=openapi.Schema(
                                            type=openapi.TYPE_OBJECT,
                                            properties={
                                                'contact_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of SOS contact (Email or Phone)"),
                                                'id': openapi.Schema(type=openapi.TYPE_STRING, description="Contact ID"),
                                                'name': openapi.Schema(type=openapi.TYPE_STRING, description="Name of the contact"),
                                                'relation': openapi.Schema(type=openapi.TYPE_STRING, description="Relation to the user"),
                                                'contact_info': openapi.Schema(type=openapi.TYPE_STRING, description="Email or phone number of the contact"),
                                                'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Verification status of the contact"),
                                                'allow_whatsapp': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Allow WhatsApp (if contact is a phone)"),
                                                'allow_sms': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Allow SMS (if contact is a phone)"),
                                                'allow_call': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Allow calling (if contact is a phone)"),
                                            }
                                        ),
                                    ),
                                }
                            ),
                        ),
                        'sos_contacts': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'contact_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of SOS contact (Email or Phone)"),
                                    'id': openapi.Schema(type=openapi.TYPE_STRING, description="Contact ID"),
                                    'name': openapi.Schema(type=openapi.TYPE_STRING, description="Name of the contact"),
                                    'relation': openapi.Schema(type=openapi.TYPE_STRING, description="Relation to the user"),
                                    'contact_info': openapi.Schema(type=openapi.TYPE_STRING, description="Email or phone number of the contact"),
                                    'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Verification status of the contact"),
                                    'allow_whatsapp': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Allow WhatsApp (if contact is a phone)"),
                                    'allow_sms': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Allow SMS (if contact is a phone)"),
                                    'allow_call': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Allow calling (if contact is a phone)"),
                                }
                            ),
                        ),
                    }
                )
            ),
            401: "Unauthorized. Access token is missing or invalid."
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def get(self, request):
        user_devices = Device.objects.filter(user=request.user)
        total_devices = user_devices.count()
        # Count activated and inactive devices
        activated_devices_count = user_devices.filter(device_status="active").count()
        inactive_devices_count = user_devices.filter(device_status="inactive").count()
        latest_email = SOSEmails.objects.filter(user=request.user).order_by('-updated_at').first()
        latest_phone = SOSPhones.objects.filter(user=request.user).order_by('-updated_at').first()
        if latest_email and (not latest_phone or latest_email.updated_at > latest_phone.updated_at):
            latest_contact = latest_email.updated_at
        elif latest_phone:
            latest_contact = latest_phone.updated_at
        else:
            latest_contact = None

        # Get the most recent notification time
        latest_notification = NotificationLog.objects.filter(device__in=user_devices).order_by('-updated_at').first()
        latest_notification_time = latest_notification.updated_at if latest_notification else None

        # Get the total number of notifications related to the user's devices
        total_notifications = Event.objects.filter(device__in=user_devices).count()

        # Retrieve and count SOS contacts for the user
        user_sos_emails = SOSEmails.objects.filter(user=request.user)
        user_sos_phones = SOSPhones.objects.filter(user=request.user)
        user_sos_email = SOSEmails.objects.filter(user=request.user).values('name', 'relation').distinct()
        user_sos_phone = SOSPhones.objects.filter(user=request.user).values('name', 'relation').distinct()

        # Combine the emails and phones contacts manually
        combined_contacts = []
        combined_contacts.extend(user_sos_email)
        combined_contacts.extend(user_sos_phone)

        # Remove duplicates (if any) based on 'name' and 'relation' pairs
        unique_contacts = {f"{contact['name']}-{contact['relation']}": contact for contact in combined_contacts}
        total_soscontacts = len(unique_contacts)

        # Prepare devices data with associated contacts
        devices_data = []
        for device in user_devices:
            email_contacts = device.sos_emails.all()
            phone_contacts = device.sos_phones.all()

            # Format contacts data for each device
            contacts_data = [
                {
                    'contact_type': 'Email',
                    'id': email.id,
                    'name': email.name,
                    'relation': email.relation,
                    'contact_info': email.emails,
                    'is_verified': email.is_verified,
                }
                for email in email_contacts
            ] + [
                {
                    'contact_type': 'Phone',
                    'id': phone.id,
                    'name': phone.name,
                    'relation': phone.relation,
                    'country_code': phone.country_code,
                    'contact_info': phone.phone_numbers,
                    'is_verified': phone.is_verified,
                    'allow_whatsapp': phone.allow_whatsapp,
                    'allow_sms': phone.allow_sms,
                    'allow_call': phone.allow_call,
                }
                for phone in phone_contacts
            ]

            # Append each device with its contacts
            devices_data.append({
                'id': device.id,
                'device_name': device.device_name,
                'mac_address': device.mac_address,
                'description': device.description,
                'device_status': device.device_status,
                'created_at': device.created_at,
                'contacts': contacts_data,
            })

        # Prepare SOS contacts data (all contacts for the user, regardless of device)
        sos_contacts_data = [
            {
                'contact_type': 'Email',
                'id': email.id,
                'name': email.name,
                'relation': email.relation,
                'contact_info': email.emails,
                'is_verified': email.is_verified,
            }
            for email in user_sos_emails
        ] + [
            {
                'contact_type': 'Phone',
                'id': phone.id,
                'name': phone.name,
                'relation': phone.relation,
                'country_code': phone.country_code,
                'contact_info': phone.phone_numbers,
                'is_verified': phone.is_verified,
                'allow_whatsapp': phone.allow_whatsapp,
                'allow_sms': phone.allow_sms,
                'allow_call': phone.allow_call,
            }
            for phone in user_sos_phones
        ]

        # Prepare response
        return Response({
            'total_devices': total_devices,
            'activated_devices': activated_devices_count,
            'inactive_devices': inactive_devices_count,
            'total_notifications': total_notifications,
            'total_soscontacts': total_soscontacts,
            'devices': devices_data,  # list of devices and their contacts
            'latest_contact': latest_contact,  # list of devices and their contacts
            'latest_notification_time': latest_notification_time,  # list of devices and their contacts
            'sos_contacts': sos_contacts_data,  # list of all SOS contacts
        })
class RegisterDeviceAPIView(APIView):
    """
    API to register a device for the logged-in user.
    """
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated]  

    @swagger_auto_schema(
        operation_description="Register a new device for the logged-in user.",
        request_body=DeviceRegisterSerializer,
        responses={
            201: openapi.Response(
                description="Device created successfully",
                schema=DeviceRegisterSerializer,
            ),
            400: openapi.Response(
                description="Bad Request. Validation failed.",
            ),
            401: "Unauthorized. Access token is missing or invalid.",
            403: "Forbidden. Device limit exceeded."
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],  
    )
    
    def post(self, request):
        """
        Handle POST request to register a new device.
        """
        user_plan = request.user.plan
        max_buttons = user_plan.max_button
        device = Device.objects.filter(user=request.user)
        device_count = device.count()
        
        # Check if the user has reached the maximum device limit
        if device_count >= max_buttons:
            return Response(
                {"detail": _("Button limit exceeded. You cannot register more buttons.")},
                status=status.HTTP_403_FORBIDDEN
            )

        # Proceed with device registration if the limit is not reached
        serializer = DeviceRegisterSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            device = serializer.save()  
            return Response(DeviceRegisterSerializer(device).data, status=status.HTTP_201_CREATED)  
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeviceDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get device details along with related events and combined SOS contacts.",
        responses={
            200: openapi.Response(
                description="Device and events retrieved successfully.",
                schema=DeviceDetailSerializer,
            ),
            404: "Device not found.",
            401: "Unauthorized. Access token is missing or invalid."
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def get(self, request, device_id):
        """
        Retrieve the device and its associated events for the logged-in user, 
        and return combined SOS contacts both assigned to the device and for the user.
        """
        try:
            # Get the device by id for the logged-in user
            device = Device.objects.get(id=device_id, user=request.user)

            # Get only SOS emails and phones assigned to this device
            device_sosemails = device.sos_emails.all()
            device_sosphones = device.sos_phones.all()

            # Query all SOS emails and phones for the user (not just the device)
            user_sosemails = SOSEmails.objects.filter(user=request.user)
            user_sosphones = SOSPhones.objects.filter(user=request.user)

            # Combine all SOS contacts for the device
            device_sos_contacts = {}

            # Process SOS Emails for the device
            for email in device_sosemails:
                contact_reference = email.contact_reference
                if contact_reference not in device_sos_contacts:
                    device_sos_contacts[contact_reference] = {
                        'contact_reference': contact_reference,
                        'name': email.name,
                        'relation': email.relation,
                        'emails': [],
                        'phones': [],
                    }
                device_sos_contacts[contact_reference]['emails'].append({
                    'email_id': email.id,
                    'email': email.emails,
                    'is_verified': email.is_verified,
                })

            # Process SOS Phones for the device
            for phone in device_sosphones:
                contact_reference = phone.contact_reference
                if contact_reference not in device_sos_contacts:
                    device_sos_contacts[contact_reference] = {
                        'contact_reference': contact_reference,
                        'name': phone.name,
                        'relation': phone.relation,
                        'emails': [],
                        'phones': [],
                    }
                device_sos_contacts[contact_reference]['phones'].append({
                    'phone_id': phone.id,
                    'country_code': phone.country_code,
                    'phone_numbers': phone.phone_numbers,
                    'is_verified': phone.is_verified,
                    'allow_whatsapp': phone.allow_whatsapp,
                    'allow_sms': phone.allow_sms,
                    'allow_call': phone.allow_call,
                })

            # Convert device_sos_contacts to a list of dicts for the response
            device_sos_contacts_data = list(device_sos_contacts.values())

            # Count total unique SOS contacts assigned to the device
            total_soscontacts = len(device_sos_contacts)

            # Combine all SOS contacts for the user
            user_all_sos_contacts = {}

            # Process SOS Emails for the user
            for email in user_sosemails:
                contact_reference = email.contact_reference
                if contact_reference not in user_all_sos_contacts:
                    user_all_sos_contacts[contact_reference] = {
                        'contact_reference': contact_reference,
                        'name': email.name,
                        'relation': email.relation,
                        'emails': [],
                        'phones': [],
                    }
                user_all_sos_contacts[contact_reference]['emails'].append({
                    'email_id': email.id,
                    'email': email.emails,
                    'is_verified': email.is_verified,
                })

            # Process SOS Phones for the user
            for phone in user_sosphones:
                contact_reference = phone.contact_reference
                if contact_reference not in user_all_sos_contacts:
                    user_all_sos_contacts[contact_reference] = {
                        'contact_reference': contact_reference,
                        'name': phone.name,
                        'relation': phone.relation,
                        'emails': [],
                        'phones': [],
                    }
                user_all_sos_contacts[contact_reference]['phones'].append({
                    'phone_id': phone.id,
                    'country_code': phone.country_code,
                    'phone_numbers': phone.phone_numbers,
                    'is_verified': phone.is_verified,
                    'allow_whatsapp': phone.allow_whatsapp,
                    'allow_sms': phone.allow_sms,
                    'allow_call': phone.allow_call,
                })

            # Convert user_all_sos_contacts to a list of dicts for the response
            user_all_sos_contacts_data = list(user_all_sos_contacts.values())

            # Filter events based on the device and logged-in user
            events = Event.objects.filter(device=device).order_by('-created_at')

            # Serialize the device data
            device_serializer = DeviceDetailSerializer(device)

            # Prepare events data with associated videos
            event_data = []
            for event in events:
                # Serialize the event using EventSerializer
                event_dict = EventSerializer(event).data
                
                # `video_url` is already included in the serialized data
                event_data.append(event_dict)
            # Return the device, events (with videos), both device-specific and user-wide SOS contacts
            return Response({
                'device': device_serializer.data,
                'device_sos_contacts_data': device_sos_contacts_data,  # Send device-specific SOS contacts
                'total_soscontacts': total_soscontacts,
                'user_all_sos_contacts_data': user_all_sos_contacts_data,  # Send user-wide SOS contacts
                'events': event_data,
            }, status=status.HTTP_200_OK)

        except Device.DoesNotExist:
            return Response({"detail": "Device not found."}, status=status.HTTP_404_NOT_FOUND)




class DeviceUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, device_id):
        return get_object_or_404(Device, id=device_id, user=self.request.user)

    @swagger_auto_schema(
        operation_description="Update the details of a device for the logged-in user.",
        request_body=DeviceUpdateSerializer,
        responses={
            200: DeviceUpdateSerializer,
            400: openapi.Response("Bad Request. Invalid data."),
            404: openapi.Response("Device not found"),
            401: openapi.Response("Unauthorized access")
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],  # Ensure the token is part of the security definition
    )
    def put(self, request, device_id):
        device = self.get_object(device_id)
        serializer = DeviceUpdateSerializer(device, data=request.data)

        if serializer.is_valid():
            serializer.save(user=self.request.user)  # Ensure the user is set
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ToggleDeviceStatusView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure user is authenticated


    @swagger_auto_schema(
        operation_description="Toggle the device status between 'Active' and 'Inactive'.",
        responses={
            200: openapi.Response(
                description="Device status toggled successfully.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
            ),
            400: "Bad request.",
            401: "Unauthorized. Access token is missing or invalid."
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}]  # This ensures the security is linked to the bearer token
    )
    def post(self, request, device_id):
        """
        Toggle the status of a device between 'Active' and 'Inactive'.
        """
        # Ensure the device belongs to the logged-in user
        device = get_object_or_404(Device, id=device_id, user=request.user)

        # Toggle device status
        if device.device_status == 'Active':
            device.device_status = 'Inactive'
        else:
            device.device_status = 'Active'
        
        device.save()
        
        # Return a success response
        return Response(
            {'status': 'success'},  
            status=status.HTTP_200_OK
        )

class DeviceDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a device for the logged-in user.",
        responses={
            204: openapi.Response("Device deleted successfully"),
            404: openapi.Response("Device not found"),
            401: openapi.Response("Unauthorized access")
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],  # Ensure the token is part of the security definition
    )
    def delete(self, request, device_id):
        device = get_object_or_404(Device, id=device_id, user=request.user)
        device.delete()
        return Response({'status': 'success', 'message': _('Device deleted successfully.')}, status=status.HTTP_204_NO_CONTENT) 


class GetDeviceByMacAddressView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_description="Retrieve device details based on MAC address. Triggers an internal function if the device is found.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["mac_address"],
            properties={
                'mac_address': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The MAC address of the device.",
                    example="00:1B:44:11:3A:B7"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description="Device found successfully.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'device_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'mac_address': openapi.Schema(type=openapi.TYPE_STRING),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                        'device_status': openapi.Schema(type=openapi.TYPE_STRING),
                        # Add more fields if needed
                    }
                )
            ),
            400: openapi.Response(description="MAC address is required."),
            404: openapi.Response(description="Device not found."),
        }
    )

    def post(self, request, *args, **kwargs):
        mac_address = request.data.get('mac_address')
        
        if not mac_address:
            return Response({'error': 'mac_address is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            device = Device.objects.get(mac_address=mac_address)
        except Device.DoesNotExist:
            return Response({'error': 'Device not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = DeviceSerializer(device, context={'request': request}) 
        button_name = serializer.data.get('device_name')
        location = serializer.data.get('description')

        user =device.user
        ice_button_pressed(user, button_name, location)
        
        
        return Response(serializer.data, status=status.HTTP_200_OK)


class NotificationLogCreateView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        mac_address = request.data.get('mac_address', None)

        if not mac_address:
            return Response({'error': _('mac_address is required')}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = NotificationLogCreateSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class DeviceListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a list of devices associated with the logged-in user, along with total counts for devices, notifications, and SOS contacts. Each device includes its own associated SOS contacts.",
        responses={
            200: openapi.Response(
                description="List of devices and associated SOS contacts retrieved successfully.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'devices': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="Device ID"),
                                    'device_name': openapi.Schema(type=openapi.TYPE_STRING, description="Name of the device"),
                                    'mac_address': openapi.Schema(type=openapi.TYPE_STRING, description="MAC address of the device"),
                                    'device_status': openapi.Schema(type=openapi.TYPE_STRING, description="Current status of the device"),
                                    'created_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time', description="Device creation timestamp"),
                                    'contacts': openapi.Schema(
                                        type=openapi.TYPE_ARRAY,
                                        items=openapi.Schema(
                                            type=openapi.TYPE_OBJECT,
                                            properties={
                                                'contact_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of contact (Email or Phone)"),
                                                'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="Contact ID"),
                                                'name': openapi.Schema(type=openapi.TYPE_STRING, description="Name of the contact person"),
                                                'relation': openapi.Schema(type=openapi.TYPE_STRING, description="Relationship to the user"),
                                                'contact_info': openapi.Schema(type=openapi.TYPE_STRING, description="Contact information (email or phone number)"),
                                                'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Whether the contact has been verified"),
                                                'allow_whatsapp': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Permission to send WhatsApp messages", default=None),
                                                'allow_sms': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Permission to send SMS messages", default=None),
                                                'allow_call': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Permission to make calls", default=None),
                                            }
                                        ),
                                        description="List of SOS contacts associated with the device"
                                    )
                                }
                            ),
                            description="List of devices for the user with their associated SOS contacts"
                        ),
                        'sos_contacts': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'contact_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of contact (Email or Phone)"),
                                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="Contact ID"),
                                    'name': openapi.Schema(type=openapi.TYPE_STRING, description="Name of the contact person"),
                                    'relation': openapi.Schema(type=openapi.TYPE_STRING, description="Relationship to the user"),
                                    'contact_info': openapi.Schema(type=openapi.TYPE_STRING, description="Contact information (email or phone number)"),
                                    'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Whether the contact has been verified"),
                                    'allow_whatsapp': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Permission to send WhatsApp messages", default=None),
                                    'allow_sms': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Permission to send SMS messages", default=None),
                                    'allow_call': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Permission to make calls", default=None),
                                }
                            ),
                            description="List of all SOS contacts for the user"
                        )
                    }
                )
            ),
            401: openapi.Response(description="Unauthorized. Access token is missing or invalid.")
        },
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}]  # Links the endpoint to the Bearer token for security
    )
    def get(self, request):
        user_devices = Device.objects.filter(user=request.user)

        # Prepare devices data with associated contacts
        devices_data = []
        for device in user_devices:
            # Get SOS email and phone contacts assigned to this device
            device_sos_email = device.sos_emails.values('name', 'relation').distinct()
            device_sos_phone = device.sos_phones.values('name', 'relation').distinct()

            # Combine the email and phone contacts for this device
            combined_device_contacts = []
            combined_device_contacts.extend(device_sos_email)
            combined_device_contacts.extend(device_sos_phone)

            # Remove duplicates based on 'name' and 'relation'
            unique_device_contacts = {f"{contact['name']}-{contact['relation']}": contact for contact in combined_device_contacts}

            # Total unique SOS contacts assigned to this device
            total_contacts = len(unique_device_contacts)

            # Append device data with the total unique SOS contacts
            devices_data.append({
                'id': device.id,
                'device_name': device.device_name,
                'mac_address': device.mac_address,
                'description': device.description,
                'device_status': device.device_status,
                'created_at': device.created_at,
                'total_contacts': total_contacts,  # Total unique SOS contacts for this device
            })

        # Prepare the final response
        return Response({
            'devices': devices_data,  # List of devices and their unique SOS contacts
        })


class EventListAPIView(APIView):
    """
    API View to retrieve a list of events for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a list of events for the authenticated user.",
        responses={
            200: EventSerializer(many=True),
            401: "Unauthorized"
        },
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}]
    )
    def get(self, request, *args, **kwargs):
        """
        Retrieve the authenticated user's events.
        """
        events = Event.objects.filter(user=request.user).order_by('-created_at')
        serializer = EventSerializer(events, many=True)
        
        return Response({
            "status": "success",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

class NotificationLogsAPIView(APIView):
    """
    API View to retrieve notification logs for a specific event.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve notification logs for a specific event associated with the authenticated user.",
        responses={
            200: NotificationLogSerializer(many=True),
            404: "Event not found"
        },
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}]
    )
    def get(self, request, event_id, *args, **kwargs):
        """
        Retrieve logs related to a specific event for the authenticated user.
        """
        user = request.user
        event = get_object_or_404(Event, id=event_id, user=user)

        # Fetch logs related to the event
        logs = event.notifications.select_related('device').order_by('-created_at')
        
        # Serialize logs
        serializer = NotificationLogSerializer(logs, many=True)
        
        return Response({
            "status": "success",
            "event": EventSerializer(event).data,
            "logs": serializer.data
        }, status=status.HTTP_200_OK)


class GetProfileAPIView(APIView):
    """
    API endpoint to retrieve the logged-in user's profile.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the profile of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Profile retrieved successfully.",
                schema=UserProfileSerializer,
            ),
            401: openapi.Response(
                description="Unauthorized. Access token is missing or invalid.",
            ),
        },
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}]  # This ensures the security is linked to the bearer token
    )
    def get(self, request):
        """
        Retrieve the logged-in user's profile.
        """
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# API view for updating the user's profile
class UpdateProfileAPIView(APIView):
    """
    API endpoint to update the logged-in user's profile.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update the profile of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Profile updated successfully.",
                schema=UserProfileSerializer,
            ),
            400: openapi.Response(
                description="Bad Request. Validation failed or invalid data provided.",
            ),
            401: openapi.Response(
                description="Unauthorized. Access token is missing or invalid.",
            ),
        },
        request_body=UserProfileSerializer,  # Serializer used for updating the profile
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}]  # This ensures the security is linked to the bearer token
    )
    def put(self, request):
        """
        Update the logged-in user's profile.
        """
        serializer = UserProfileSerializer(request.user, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"detail": _("Profile updated successfully!")}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileImageAPIView(APIView):
    """
    API endpoint to update or delete the profile image of the logged-in user.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # Ensure file upload is handled

    @swagger_auto_schema(
        operation_description="Update the profile image of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Profile image updated successfully.",
                schema=ProfileImageUpdateSerializer,
            ),
            400: openapi.Response(
                description="Bad Request. Validation failed or invalid data provided.",
            ),
            401: openapi.Response(
                description="Unauthorized. Access token is missing or invalid.",
            ),
        },
        request_body=ProfileImageUpdateSerializer,  # Use the serializer for updating the image
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}],  # Security is linked to the bearer token
        consumes=["multipart/form-data"]  # Allows file uploads for the profile image
    )
    
    def post(self, request):
        """
        Update the profile image of the logged-in user.
        """
        serializer = ProfileImageUpdateSerializer(request.user, data=request.data)

        if serializer.is_valid():
            # Save the image update
            serializer.save()
            return Response({"detail": "Profile image updated successfully!"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Delete the profile image of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Profile image deleted successfully.",
            ),
            400: openapi.Response(
                description="Bad Request. Validation failed or invalid data provided.",
            ),
            401: openapi.Response(
                description="Unauthorized. Access token is missing or invalid.",
            ),
        },
        manual_parameters=[bearer_token],  # Includes the bearer token in the Swagger UI
        security=[{'Bearer': []}],  # Security is linked to the bearer token
    )

    def delete(self, request):
        """
        Delete the profile image of the logged-in user.
        """
        if request.user.profile_image:
            request.user.profile_image.delete()  # Delete the profile image
            return Response({"detail": _("Profile image deleted successfully!")}, status=status.HTTP_200_OK)
        
        return Response({"detail": _("No profile image found to delete.")}, status=status.HTTP_400_BAD_REQUEST)


class DeviceVideoUploadView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser]
    queryset = DeviceVideo.objects.all()
    serializer_class = DeviceVideoSerializer

    def perform_create(self, serializer):
        try:
            print("Performing video upload...")
            video_file = self.request.FILES.get('video')  # Get directly from request to avoid .read() issues

            if not video_file or video_file.size == 0:
                raise serializers.ValidationError({"video": "Empty or missing video file."})

            user = serializer.validated_data['user']
            device = serializer.validated_data['device']

            extension = os.path.splitext(video_file.name)[1]
            new_filename = f"{user.username}_{uuid.uuid4().hex}{extension}"

            cloudinary_response = upload(
                video_file,
                resource_type="video",
                public_id=new_filename,
                filename=video_file.name
            )
            video_url = cloudinary_response['secure_url']
            print(f"Video uploaded to Cloudinary: {video_url}")

            # Save instance WITHOUT the file (only user/device/event info)
            serializer.validated_data.pop('video', None)  # Don't pass file to model
            video_instance = serializer.save()

            video_instance.set_video_url(video_url)

            self._send_notification_emails(video_instance)

        except CloudinaryError as e:
            logging.error(f"Cloudinary upload failed: {e}")
            raise serializers.ValidationError({"video": f"Cloudinary upload failed: {e}"})
        except Exception as e:
            logging.error(f"Video processing failed: {e}")
            raise serializers.ValidationError({"error": f"Video processing failed: {e}"})

    def _send_notification_emails(self, video_instance):
        try:
            video_url = video_instance.video_url
            print("lelelelelele",video_url)
            user = video_instance.user
            user_plan = user.plan
            
            emails = SOSEmails.objects.filter(
                user=user,
                is_verified=True
            ).values_list('emails', flat=True)[:user_plan.max_emails]

            for email in emails:
                try:
                    subject = "Emergency Alert: Video Recording Link"
                    message = render_to_string(
                        'email/emergency_alert_email.html',
                        {'video_url': video_url}
                    )

                    email_message = EmailMultiAlternatives(
                        subject=subject,
                        body=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[email.strip()]
                    )
                    email_message.attach_alternative(message, "text/html")
                    email_message.send()
                    print(f"Email sent to {email}")
                except Exception as e:
                    logging.error(f"Failed to send email to {email}: {e}")

        except Exception as e:
            logging.error(f"Notification processing failed: {e}")

class VideoListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensures only authenticated users can access this view

    @swagger_auto_schema(
        operation_description="Retrieve a list of videos associated with the logged-in user, ordered by upload date.",
        responses={
            200: openapi.Response(
                description="List of videos retrieved successfully.",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'video_url': openapi.Schema(type=openapi.TYPE_STRING, format='uri'),
                            'uploaded_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                            'device': openapi.Schema(type=openapi.TYPE_STRING), 
                        }
                    )
                ),
            ),
            401: openapi.Response(description="Unauthorized. Access token is missing or invalid.")
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}]  
    )
    def get(self, request):
        """
        Retrieve a list of videos for the authenticated user.
        """
        videos = DeviceVideo.objects.filter(user=request.user).order_by('-uploaded_at')

        serializer = DeviceVideoListSerializer(videos, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class ViewVideoAPIView(APIView):
    """
    API view to retrieve details of a specific video by ID.
    """
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    @swagger_auto_schema(
        operation_description="Retrieve details of a video by ID.",
        responses={
            200: openapi.Response(
                description="Video details retrieved successfully",
                schema=DeviceVideoSerializer(),
            ),
            404: openapi.Response(
                description="Video not found",
                examples={"application/json": {"status": "error", "message": "Video not found."}},
            ),
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}] 
        
    )
    def get(self, request, video_id):
        video = get_object_or_404(DeviceVideo, id=video_id)

        serializer = DeviceVideoSerializer(video)

        return Response(
            {
                "status": "success",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )

class DeleteVideoAPIView(APIView):
    """
    API endpoint to delete a video file associated with a given `video_id`.
    The video file is deleted from the local filesystem, and the corresponding
    database entry is also removed.
    """
    permission_classes = [IsAuthenticated]  # Ensure user is authenticated

    def delete(self, request, video_id):
        """
        Deletes the video file from the local filesystem and removes the database entry.
        """
        # Get the video object or return 404 if not found
        video = get_object_or_404(DeviceVideo, id=video_id)

        # Get the file path of the video
        video_path = video.video.path
        
        # Delete the video file from the local filesystem
        if os.path.exists(video_path):
            os.remove(video_path)
        else:
            return Response(
                {"detail": "Video file does not exist on the server."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Delete the video entry from the database
        video.delete()

        # Return a success response
        return Response({"detail": _("Video deleted successfully.")}, status=status.HTTP_200_OK)
   
class ConnectWifiAPIView(APIView):
    permission_classes = [AllowAny]
    """
    API endpoint to check connectivity to the panic button hotspot (Wi-Fi).
    It performs a HEAD request to the target IP and returns status information.
    """
    
    def get(self, request):
        try:
            # Attempt to connect to the hotspot URL
            response = requests.get("http://192.168.4.1", timeout=25)

            if response.status_code == 200:
                return JsonResponse({
                    "status": "success",
                    "message": _("Connected successfully to the hotspot!"),
                }, status=200)
            else:
                return JsonResponse({
                    "status": "error",
                    "message": f"Failed to connect to the hotspot. HTTP Status: {response.status_code}",
                }, status=response.status_code)
        except requests.exceptions.ConnectionError:
            return JsonResponse({
                "status": "error",
                "message": _("Unable to connect to the hotspot. Please ensure the device is connected."),
            }, status=503)
        except requests.exceptions.Timeout:
            return JsonResponse({
                "status": "error",
                "message": _("Connection to the hotspot timed out. Please try again."),
            }, status=504)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"An unexpected error occurred: {str(e)}",
            }, status=500)


class GetStreamAPIView(APIView):
    permission_classes = [IsAuthenticated]
    """
    API endpoint to fetch the stream details of the logged-in user's devices,
    with stream key bound to the specified URL format.
    """
    @swagger_auto_schema(
        operation_description="Retrieve a list of stream details for the logged-in user's devices, with stream key in URL format.",
        responses={
            200: openapi.Response(
                description="List of device stream details retrieved successfully.",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'device_name': openapi.Schema(type=openapi.TYPE_STRING, description="The name of the device"),
                            'mac_address': openapi.Schema(type=openapi.TYPE_STRING, description="The MAC address of the device"),
                            'stream_url': openapi.Schema(type=openapi.TYPE_STRING, description="URL with stream key"),
                            'created_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME, description="When the entry was created"),
                            'updated_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME, description="When the entry was last updated"),
                        }
                    )
                ),
            ),
            401: openapi.Response(description="Unauthorized. Access token is missing or invalid.")
        },
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}]
    )
    def get(self, request, *args, **kwargs):
        user = request.user  # Get the logged-in user
        
        # Fetch DeviceStream objects for devices owned by the logged-in user
        device_streams = DeviceStream.objects.filter(device__user=user)

        base_url = settings.STREAM_BASE_URL
        # Serialize the data and bind the stream key to the URL
        data = [
            {
                "device_name": device_stream.device.device_name,
                "mac_address": device_stream.device.mac_address,
                "stream_url": f"{base_url}{device_stream.stream_key}",
                "created_at": device_stream.created_at,
                "updated_at": device_stream.updated_at,
            }
            for device_stream in device_streams
        ]

        # Return the serialized data
        return Response(data, status=status.HTTP_200_OK)









class AnswerCallView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        resp = VoiceResponse()
        resp.say("Alert! This is an emergency message from ICE Button. "
                 "Your loved one has triggered the ice button and may need immediate help. "
                 "Please check on them as soon as possible. ", 
                 voice="alice", language="en-US")

        return HttpResponse(str(resp), content_type='text/xml', status=status.HTTP_200_OK)
    


class CreateOrderView(APIView):
    permission_classes = [IsAuthenticated]  # Require authentication to access this view

    def post(self, request, *args, **kwargs):
        user = request.user
        plan_name = request.data.get('plan_name')
        amount = request.data.get('amount')

        if not plan_name or not amount:
            return Response({"error": "Plan name and amount are required."}, status=400)

        # Create Razorpay client
        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        
        try:
            # Create Razorpay order
            razorpay_order = client.order.create(
                {
                    'amount': int(amount * 100),  # Convert to paise
                    'currency': 'INR',
                    'payment_capture': 1  # Auto capture payment after success
                }
            )

            # Save the payment details to the database
            payment = PaymentHistory.objects.create(
                user=user,
                plan_name=plan_name,
                amount=amount,
                payment_status=PaymentStatus.PENDING,
                provider_order_id=razorpay_order['id'],
                payment_method=PaymentMethod.CARD,  # Default payment method, adjust as needed
                currency='INR'
            )

            return Response({
                "order_id": razorpay_order['id'],
                "amount": amount,
                "currency": "INR",
                "razorpay_key": settings.RAZORPAY_API_KEY
            })

        except Exception as e:
            return Response({"error": str(e)}, status=500)

from django.template import Template, Context


class PaymentCallbackView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        razorpay_payment_id = request.data.get('razorpay_payment_id')
        razorpay_order_id = request.data.get('razorpay_order_id')
        razorpay_signature = request.data.get('razorpay_signature')

        if not razorpay_payment_id or not razorpay_order_id or not razorpay_signature:
            return Response({"error": "Missing payment information."}, status=400)

        # Fetch the order from DB
        try:
            payment = PaymentHistory.objects.get(provider_order_id=razorpay_order_id)
        except PaymentHistory.DoesNotExist:
            return Response({"error": "Order not found."}, status=404)

        # Verify payment signature
        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }

        try:
            client.utility.verify_payment_signature(params_dict)
        except razorpay.errors.SignatureVerificationError:
            # If signature verification fails, mark the payment as failed
            payment.payment_status = PaymentStatus.FAILED
            payment.save()
            subscription_transaction_failed(payment.user, payment.plan_name)
            return Response({"error": "Payment verification failed."}, status=400)

        # If payment is verified successfully, update the payment status and save
        payment.payment_status = PaymentStatus.SUCCEEDED
        payment.payment_id = razorpay_payment_id
        payment.signature_id = razorpay_signature
        payment.processed_at = payment.updated_at  # Timestamp when payment was successfully processed
        payment.save()

        # Fetch the plan and update the user's subscription
        try:
            plan = Plan.objects.get(name=payment.plan_name,cost=payment.amount)
        except Plan.DoesNotExist:
            return Response({"error": "Plan not found."}, status=404)

        # Update the user's plan
        user = request.user
        emails = user.email  # Fetch the email
        first_name = user.first_name
        print(user.__dict__) 
        user.plan = plan
        user.expiry_date = now() + timedelta(days=30)
        user.save()
        subscription_transaction_successful(
            user=user,
            subscription_plan_name=plan.name,
            transaction_amount=payment.amount,
            expiration_date=user.expiry_date
        )
        context = {
            'user': user,
            'first_name':first_name,
            'email':emails,
            'plan_name': plan.name,
            'payment_id': payment.payment_id,
            'payment_status': payment.payment_status,
            'payment_method': payment.payment_method,
            'amount': payment.amount,
            'currency': payment.currency,
            'payment_date': payment.processed_at.strftime('%Y-%m-%d %H:%M:%S') if payment.processed_at else 'N/A',
        }

        message = render_to_string('email/email_subscription_success.html', context)

        try:
            # Create the email
            email = EmailMultiAlternatives(
                subject="Your Subscription Plan Has Been Upgraded Successfully!",
                body=message,  # Fallback plain text body
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[emails],
            )

            # Attach the HTML content
            email.attach_alternative(message, "text/html")

            # Send the email
            email.send()
        except Exception as e:
            # Handle errors (log or notify admins)
            print(f"Error sending email: {e}")

        return JsonResponse({"message": "Payment successfull"}, status=200)


class TransactionDetailsView(APIView):
    """
    API View to retrieve all transactions for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a list of all transactions for the authenticated user.",
        responses={
            200: openapi.Response(
                description="List of user's transactions",
                examples={
                    "application/json": [
                        {
                            "id": 1,
                            "transaction_id": "txn_12345",
                            "plan_name": "Premium Plan",
                            "status": "Success",
                            "transaction_amount": 1000.0,
                            "date": "2024-12-16",
                            "time": "14:30:00"
                        },
                        {
                            "id": 2,
                            "transaction_id": "txn_67890",
                            "plan_name": "Basic Plan",
                            "status": "Failed",
                            "transaction_amount": 500.0,
                            "date": "2024-12-15",
                            "time": "10:15:00"
                        }
                    ]
                }
            ),
            401: openapi.Response(description="Authentication credentials were not provided or invalid."),
        }, 
        manual_parameters=[bearer_token],  # JWT token as manual parameter
        security=[{'Bearer': []}],
    )
    def get(self, request, *args, **kwargs):
        # Fetch the user's transactions
        transactions = PaymentHistory.objects.filter(user=request.user).order_by('-created_at')

        # Serialize the data
        transaction_data = []
        for transaction in transactions:
            transaction_data.append({
                "id": transaction.id,
                "transaction_id": transaction.provider_order_id,
                "plan_name": transaction.plan_name,
                "status": transaction.payment_status,
                "transaction_amount": transaction.amount,
                "date": localtime(transaction.created_at).strftime('%Y-%m-%d'),
                "time": localtime(transaction.created_at).strftime('%H:%M:%S'),
            })

        # Return the response without pagination
        return Response(transaction_data)
    



class TransactionDetailView(APIView):
    """
    API View to retrieve transaction details by primary key (pk).
    Requires JWT authentication and returns the transaction data as JSON.
    """
    permission_classes = [IsAuthenticated]  # Only authenticated users can access

    @swagger_auto_schema(
        operation_description="Get details of a specific transaction by pk",
        responses={
            200: PaymentHistorySerializer,  # Specify the serializer class
            404: openapi.Response("Transaction not found"),  # 404 response for not found
        }, 
        manual_parameters=[bearer_token],  # JWT token as manual parameter
        security=[{'Bearer': []}],  # Security definition for JWT authentication
    )
    def get(self, request, pk):
        """
        Retrieve the details of a transaction by its primary key (pk).
        """
        try:
            # Retrieve the transaction using the primary key
            transaction = PaymentHistory.objects.get(pk=pk)
        except PaymentHistory.DoesNotExist:
            # Return 404 if the transaction is not found
            return Response({"error": "Transaction not found."}, status=404)

        # Serialize the transaction data and return it as JSON
        serializer = PaymentHistorySerializer(transaction)
        return Response(serializer.data)

class ContactUsAPIView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_description="Submit a new contact form with order details.",
        request_body=ContactUsSerializer,
        responses={
            201: openapi.Response(
                description="Emails sent successfully.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
            ),
            400: openapi.Response(
                description="Validation error.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
            ),
            500: openapi.Response(
                description="Internal server error while sending emails.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            # Save the validated data to the database
            contact = serializer.save()

            # Compose the email for support
            subject_support = f"New Order Form Submission: {contact.subject or 'No Subject'}"
            message_support = render_to_string(
                'email/order_form_submission_support.html',  # Path to your template
                {
                        'name': contact.name,
                        'organization': contact.organization,
                        'email': contact.email,
                        'phone': contact.phone or 'Not Provided',
                        'ice_quantity': contact.ice_quantity,
                        'city': contact.city,
                        'message': contact.message,
                    }
            )
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list_support = ['support@ICE-Button.com', 'kanik.gupta@mobiloitte.com']

            try:
                # Send email to support
                send_mail(subject_support, message_support, from_email, recipient_list_support, html_message=message_support)

                # Now send email to the user
                subject_user = "ICE-Button Confirmation of Your Order Form Submission"
                message_user = render_to_string(
                    'email/order_form_submission_user.html',  # Path to your user email template
                    {
                        'name': contact.name,
                        'organization': contact.organization,
                        'email': contact.email,
                        'phone': contact.phone or 'Not Provided',
                        'ice_quantity': contact.ice_quantity,
                        'city': contact.city,
                        'message': contact.message,
                    }
                )

                recipient_list_user = [contact.email]
                send_mail(subject_user, message_user, from_email, recipient_list_user, html_message=message_user)

                return Response({'success': _('Thank you for contacting us! Emails sent successfully.')},
                                status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response({'error': f'Failed to send email. Error: {str(e)}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class GetInTouchAPIView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access the API

    @swagger_auto_schema(
        operation_description="Retrieve all GetInTouch entries",
        operation_summary="Get all submitted entries",
        responses={200: GetInTouchSerializer(many=True)}
    )
    def get(self, request):
        """
        Retrieve all submitted GetInTouch entries.
        """
        entries = GetInTouch.objects.all().order_by('-created_at')
        serializer = GetInTouchSerializer(entries, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Create a new GetInTouch entry",
        operation_summary="Submit a GetInTouch form",
        request_body=GetInTouchSerializer,
        responses={201: GetInTouchSerializer, 400: 'Bad Request'}
    )
    def post(self, request):
        """
        Create a new GetInTouch entry and send email to support@ICE-Button.com and the user.
        """
        serializer = GetInTouchSerializer(data=request.data)
        if serializer.is_valid():
            # Save the validated data
            get_in_touch_entry = serializer.save()

            # Compose and send the email to the support team
            support_subject = f"New Contact Query from {get_in_touch_entry.name}"
            support_context = {
                'name': get_in_touch_entry.name,
                'email': get_in_touch_entry.email,
                'phone': get_in_touch_entry.phone_number,
                'subject': get_in_touch_entry.subject,
                'message': get_in_touch_entry.message,
            }
            support_html_content = render_to_string('email/support_email.html', support_context)

            support_email = EmailMultiAlternatives(
                subject=support_subject,
                body="New query received from the website.",  # Fallback text-only content
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=['support@ICE-Button.com', 'kanik.gupta@mobiloitte.com'],
            )
            support_email.attach_alternative(support_html_content, "text/html")
            support_email.send()

            # Compose and send the email to the user (confirmation)
            user_subject = f"Confirmation of Your Query: {get_in_touch_entry.subject}"
            user_context = support_context  # Reuse the same context
            user_html_content = render_to_string('email/user_confirmation_email.html', user_context)

            user_email = EmailMultiAlternatives(
                subject=user_subject,
                body="Thank you for reaching out to us.",  # Fallback text-only content
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[get_in_touch_entry.email],
            )
            user_email.attach_alternative(user_html_content, "text/html")
            user_email.send()

            # Return a success response
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
from googletrans import Translator

translator = Translator()

# Function to translate text
def translate_text(text, target_language='hi'):
    translated = translator.translate(text, dest=target_language)
    return translated.text

class FAQListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        cache_key = 'faq_list_data'
        cached_data = cache.get(cache_key)

        if cached_data:
            return Response(cached_data, status=status.HTTP_200_OK)

        # Fetch the FAQs
        headings = FAQHeading.objects.prefetch_related('faq_s').all()

        # Prepare the FAQ data
        faqs_data = []
        for heading in headings:
            faq_section = {
                'section_title_en': heading.title,
                'section_title_hi': translate_text(heading.title, 'hi'),
                'faq_s': []
            }

            for faq in heading.faq_s.all():
                faq_data = {
                    'question_en': faq.question,
                    'answer_en': faq.answer,
                    'question_hi': translate_text(faq.question, 'hi'),
                    'answer_hi': translate_text(faq.answer, 'hi')
                }
                faq_section['faq_s'].append(faq_data)

            faqs_data.append(faq_section)

        # Cache the data for 15 minutes
        cache.set(cache_key, faqs_data, 300)

        return Response(faqs_data, status=status.HTTP_200_OK)


    

class StaticContentDetailView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, slug):
        # Fetch content by slug
        content = get_object_or_404(StaticContent, slug=slug)
        serializer = StaticContentSerializer(content)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserLogDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve logs for the authenticated user",
        responses={200: 'Logs retrieved successfully.', 404: 'No logs found for this user.'},
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def get(self, request):
        """Retrieve logs for the authenticated user."""
        user = request.user
        cache_key = f"user_logs_{user.id}"  # Unique cache key for each user

        # Check if data is already cached
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info("Data retrieved from cache.")  # Log cache hit
            return Response(cached_data, status=status.HTTP_200_OK)

        # If not cached, fetch data from the database
        logger.info("Data not found in cache. Fetching from database.")  # Log cache miss
        logs = UserLog.objects.filter(user=user).order_by('-created_at')

        if not logs:
            return Response({"error": _("No logs found for this user.")}, status=status.HTTP_404_NOT_FOUND)

        # Add translation to the serialized data
        data = []
        for log in logs:
            original_text = log.log_message  # Assuming `log_message` is the field to translate
            translated_text = translate_text(original_text, target_language='hi')

            # Serialize the log directly without nesting under `other_fields`
            log_data = UserLogSerializer(log).data  # Serialize other fields

            # Add translated text and original text directly into the response
            log_data['original_text'] = original_text
            log_data['translated_text'] = translated_text

            data.append(log_data)

        # Cache the data for future requests (e.g., 5 minutes)
        cache.set(cache_key, data, timeout=600)
        print("sdasdadadasdadadadadas")  # 300 seconds = 5 minutes
        logger.info("Data cached successfully.")  # Log cache set

        return Response(data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="Mark a specific log as read",
        responses={200: UserLogSerializer, 404: 'Log not found.'},
        manual_parameters=[bearer_token],  # JWT token as manual parameter
        security=[{'Bearer': []}],
    )
    def put(self, request):
        """Mark a specific log as read."""
        log_id = request.data.get('log_id')
        if not log_id:
            return Response({"error": "log_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            log = UserLog.objects.get(id=log_id, user=request.user)
            log.read = True
            log.save()
            serializer = UserLogSerializer(log)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserLog.DoesNotExist:
            return Response({"error": "Log not found."}, status=status.HTTP_404_NOT_FOUND)

class UserLogDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a single log entry for the authenticated user.",
        responses={200: 'Log retrieved successfully.', 404: 'Log not found.'},
        manual_parameters=[bearer_token],
        security=[{'Bearer': []}],
    )
    def get(self, request, pk, *args, **kwargs):
        """
        Retrieve a single log entry for the authenticated user.
        """
        log = get_object_or_404(UserLog, pk=pk, user=request.user)
        original_text = log.log_message  # Assuming `text` is the field to translate
        translated_text = translate_text(original_text, target_language='hi')

        data = {
            'original_text': original_text,
            'translated_text': translated_text,
            'other_fields': UserLogSerializer(log).data  # Serialize other fields
        }

        return Response(data, status=status.HTTP_200_OK)

class DeviceStreamKeyAPI(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this API

    def post(self, request, *args, **kwargs):
        mac_address = request.data.get('mac_address')
        stream_key = request.data.get('event_id')

        if not mac_address:
            return Response({'error': 'mac_address is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not stream_key:
            return Response({'error': 'stream_key is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the device by its MAC address
            device = Device.objects.get(mac_address=mac_address)
        except Device.DoesNotExist:
            return Response({'error': 'Device not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if a DeviceStream entry already exists for the device
        device_stream = DeviceStream.objects.filter(device=device).first()

        if device_stream:
            # If a DeviceStream entry exists, update the stream key
            device_stream.stream_key = stream_key
            device_stream.save()  # Save the updated stream key
            return Response({'message': 'Stream key updated successfully', 'event_id': device_stream.stream_key}, status=status.HTTP_200_OK)
        else:
            # If no entry exists, create a new one
            device_stream = DeviceStream.objects.create(
                device=device,  # The found device
                stream_key=stream_key  # The provided stream key
            )
            return Response({'message': 'Stream key created successfully', 'event_id': device_stream.stream_key}, status=status.HTTP_201_CREATED)

####Api for the smart watch 

from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from twilio.rest import Client
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import SOSEmails, SOSPhones

class SOSTriggerView(APIView):
    """
    Trigger SOS notification to all contacts via SMS, WhatsApp, Call, and Email.
    This will only send notifications to the authenticated user's contacts.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Trigger SOS notifications for all contacts associated with the authenticated user.",
        responses={
            200: openapi.Response(description="SOS triggered successfully."),
            400: openapi.Response(description="Error triggering SOS."),
            401: openapi.Response(description="Unauthorized.")
        },
        manual_parameters=[
            openapi.Parameter(
                name="Authorization",
                in_=openapi.IN_HEADER,
                description="Bearer token for authentication (e.g., Bearer <token>).",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ]
    )
    def post(self, request):
        user = request.user

        # Fetch SOS contacts for the logged-in user
        email_contacts = SOSEmails.objects.filter(user=user)
        phone_contacts = SOSPhones.objects.filter(user=user)

        # Collect notification results
        results = {"emails_sent": 0, "sms_sent": 0, "whatsapp_sent": 0, "calls_made": 0}

        # Notify via Email
        for email_contact in email_contacts:
            if email_contact.is_verified:
                try:
                    send_mail(
                        subject="Emergency SOS Alert!",
                        message="This is an SOS alert sent from your contact!",
                        from_email="sos@example.com",
                        recipient_list=[email_contact.emails],
                        fail_silently=False,
                    )
                    results["emails_sent"] += 1
                except Exception as e:
                    print(f"Failed to send email to {email_contact.emails}: {str(e)}")

        # Get Twilio credentials from settings.py
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        # Initialize Twilio client
        twilio_client = Client(account_sid, auth_token)

        # Notify via SMS and WhatsApp
        for phone_contact in phone_contacts:
            if phone_contact.is_verified:
                # Send SMS
                if phone_contact.allow_sms:
                    try:
                        twilio_client.messages.create(
                            body="This is an SOS alert sent from your contact!",
                            from_=twilio_phone_number,
                            to=f"{phone_contact.country_code}{phone_contact.phone_numbers}",
                        )
                        results["sms_sent"] += 1
                    except Exception as e:
                        print(f"Failed to send SMS to {phone_contact.phone_numbers}: {str(e)}")

                # Send WhatsApp
                if phone_contact.allow_whatsapp:
                    try:
                        twilio_client.messages.create(
                            body="This is an SOS alert sent from your contact!",
                            from_="whatsapp:" + twilio_phone_number,
                            to="whatsapp:" + f"{phone_contact.country_code}{phone_contact.phone_numbers}",
                        )
                        results["whatsapp_sent"] += 1
                    except Exception as e:
                        print(f"Failed to send WhatsApp to {phone_contact.phone_numbers}: {str(e)}")

                # Make a Call
                if phone_contact.allow_call:
                    try:
                        twilio_client.calls.create(
                            twiml='<Response><Say>This is an emergency SOS call from your contact.</Say></Response>',
                            from_=twilio_phone_number,
                            to=f"{phone_contact.country_code}{phone_contact.phone_numbers}",
                        )
                        results["calls_made"] += 1
                    except Exception as e:
                        print(f"Failed to call {phone_contact.phone_numbers}: {str(e)}")

        return Response({
            "message": "SOS notifications triggered successfully.",
            "results": results,
        }, status=status.HTTP_200_OK)


class CheckStreamAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def normalize_mac(self, mac):
                    return mac.replace(":", "").lower()
    def get(self, request):
        try:
            # Fetch the user's device (assuming only one per user for now)
            device = Device.objects.filter(user=request.user, device_status='Active').first()

            if not device:
                return Response({"live": False, "allowed": False, "reason": "No active device assigned."})
            
            mac_address = self.normalize_mac(device.mac_address)
            print(mac_address)
            rtmp_url = f"rtmp://192.168.31.164:1935/live/{mac_address}"
            print(rtmp_url)

            is_live = self.check_stream_live(rtmp_url)

            return Response({
                "live": is_live,
                "allowed": True,
                "stream_key": mac_address
            })

        except Exception as e:
            return Response({"live": False, "allowed": False, "error": str(e)})

    def check_stream_live(self, rtmp_url):
        try:
            ffprobe_path = r"C:\ffmpeg\bin\ffprobe.exe"  # 🔁 Replace with actual path

            result = subprocess.run(
                [ffprobe_path, "-v", "error", "-show_streams", "-i", rtmp_url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=5
            )

            output = result.stdout.decode()
            print("FFPROBE OUTPUT:\n", output)

            return "[STREAM]" in output
        except Exception as e:
            print("FFPROBE EXCEPTION:", str(e))
            return False
