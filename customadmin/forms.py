import re
from django import forms
from customadmin.models import BaseUser
from core.models import *
from .models import *
from blogs.models import *
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import  PasswordChangeForm

class BlogPostForm(forms.ModelForm):
    class Meta:
        model = BlogPost
        fields = [
            'title', 'description', 'content', 'created_by', 'image', 'category', 
            'quote_text', 'quote_author', 'tags', 'bulleted_points', 'extra_images', 'extra_content'
        ]

    created_by = forms.ModelChoiceField(queryset=Profile.objects.all(), required=False)



class BulletedPointForm(forms.ModelForm):
    class Meta:
        model = BulletedPoint
        fields = ['text', 'image']

class TagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ['name']

class BlogImageForm(forms.ModelForm):
    class Meta:
        model = BlogImage
        fields = ['image', 'description']

class StaticContentForm(forms.ModelForm):
    class Meta:
        model = StaticContent
        fields = ['title', 'slug', 'body', 'meta_title', 'meta_description']

class FAQHeadingForm(forms.ModelForm):
    class Meta:
        model = FAQHeading
        fields = ['title', 'description']

class FAQsForm(forms.ModelForm):
    class Meta:
        model = FAQs
        fields = ['heading', 'question', 'answer']

class FAQUpdateForm(forms.ModelForm):
    class Meta:
        model = FAQs
        fields = ['question', 'answer']

        # Custom labels for form fields
        labels = {
            'question': 'FAQ Question',
            'answer': 'FAQ Answer',
        }

        # Custom widgets for form fields
        widgets = {
            'question': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter the question here',
                'rows': 4,
            }),
            'answer': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Provide the answer here',
                'rows': 6,
            }),
        }

class PlanForm(forms.ModelForm):
    stream_length_minutes = forms.IntegerField(min_value=0, required=False, label='Stream Length Minutes')
    stream_length_seconds = forms.IntegerField(min_value=0, required=False, label='Stream Length Seconds')

    class Meta:
        model = Plan
        fields = ['name', 'max_emails', 'max_phone_numbers', 'max_button', 'stream', 'cost','subscription_type']
        labels = {
            'name': 'Plan Name',
            'max_emails': 'Max Emails',
            'max_phone_numbers': 'Max Phone Numbers',
            'max_button': 'Maximum Buttons',
            'stream': 'Live Stream',
            'cost': 'Cost ($)',
        }
        help_texts = {
            'name': 'Enter the name of the plan (max 50 characters).',
            'max_emails': 'Maximum number of emails allowed.',
            'max_phone_numbers': 'Maximum number of phone numbers allowed.',
            'max_button': 'Maximum number of buttons allowed.',
            'cost': 'Enter the cost for this plan (must be positive).',
        }

    def clean_max_emails(self):
        max_emails = self.cleaned_data.get('max_emails')
        if max_emails <= 0:
            raise forms.ValidationError("Max emails must be a positive number.")
        return max_emails

    def clean_max_phone_numbers(self):
        max_phone_numbers = self.cleaned_data.get('max_phone_numbers')
        if max_phone_numbers <= 0:
            raise forms.ValidationError("Max phone numbers must be a positive number.")
        return max_phone_numbers

    def clean_max_button(self):
        max_button = self.cleaned_data.get('max_button')
        if max_button <= 0:
            raise forms.ValidationError("Max buttons must be a positive number.")
        return max_button

    def clean_cost(self):
        cost = self.cleaned_data.get('cost')
        if cost < 0:
            raise forms.ValidationError("Cost must be a positive number.")
        return cost

    def clean_stream_length(self):
        minutes = self.cleaned_data.get('stream_length_minutes') or 0
        seconds = self.cleaned_data.get('stream_length_seconds') or 0

        try:
            stream_length = timedelta(minutes=int(minutes), seconds=int(seconds))
            
            return stream_length
        except (ValueError, TypeError):
            raise forms.ValidationError("Invalid values for minutes or seconds.")
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = BaseUser
        max_length = 21
        fields = ['first_name', 'last_name', 'email', 'username']
        labels = {
            'first_name': 'First Name',
            'last_name': 'Last Name',
            'email': 'Email Address',
            'username': 'Username',
            'maxlength': '21'
        }
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
        }

class UserEditForm(forms.ModelForm):
    class Meta:
        model = BaseUser
        fields = ['username', 'email', 'phone_number',]
        widgets = {
            'phone_number': forms.TextInput(attrs={'placeholder': 'Enter phone number'}),
        }

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if phone_number and len(phone_number) < 13:
            raise forms.ValidationError("Phone number must be at least 13 digits long.")
        return phone_number

class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label='Old password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Old Password'})
    )
    new_password1 = forms.CharField(
        label='New password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'})
    )
    new_password2 = forms.CharField(
        label='Confirm new password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm New Password'})
    )

class AdminDeviceForm(forms.ModelForm):
    email = forms.EmailField(
        label='User Email',
        max_length=50,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter User Email',
            'title': 'Email of the user to whom the button will be assigned'
        })
    )

    class Meta:
        model = Device
        fields = [
            'email',
            'device_name', 'mac_address', 'message',
            'device_status'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ensure consistent styling
        for field in self.fields:
            self.fields[field].widget.attrs.update({'class': 'form-control'})

        # Initialize email field if instance exists
        if self.instance and self.instance.pk:
            if self.instance.user:
                self.fields['email'].initial = self.instance.user.email

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email:
            raise ValidationError("User email is required.")
        if not BaseUser.objects.filter(email=email).exists():
            raise ValidationError("User with this email does not exist.")
        return email

    def save(self, commit=True):
        device = super().save(commit=False)
        email = self.cleaned_data.get('email')
        if email:
            user = BaseUser.objects.get(email=email)
            device.user = user
        if commit:
            device.save()
        return device
    

class CreateUserForm(forms.ModelForm):
    class Meta:
        model = BaseUser  # Specify your custom user model
        fields = ['username', 'email', 'phone_number']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter username', 'maxlength': 20}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter email', 'maxlength': 50}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter phone number', 'maxlength': 15}),
        }

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if len(phone_number) > 15:
            raise forms.ValidationError('Phone number cannot exceed 12 digits.')
        return phone_number

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if BaseUser.objects.filter(email=email).exists():
            raise forms.ValidationError('Email is already in use. Please use a different email.')
        return email