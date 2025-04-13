from django.contrib.auth.backends import BaseBackend
from customadmin.models import BaseUser
from customadmin.models import BaseUser

class BaseUserBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Determine if the username is an email or username
        try:
            if '@' in username:
                user = BaseUser.objects.get(email=username)
            else:
                user = BaseUser.objects.get(username=username)
        except BaseUser.DoesNotExist:
            return None

        if user.check_password(password):
            return user
        return None

    def get_user(self, user_id):
        try:
            return BaseUser.objects.get(pk=user_id)
        except BaseUser.DoesNotExist:
            return None
