from django.utils.crypto import salted_hmac
from django.utils.http import urlsafe_base64_encode
import hashlib

class SubscriberTokenGenerator:
    def make_token(self, subscriber):
        """
        Generates a token for the subscriber.
        """
        timestamp = str(subscriber.subscribed_at.timestamp())  # Use the subscription timestamp as part of the token
        value = f"{subscriber.pk}-{timestamp}"
        return self._make_hash_value(value)
    
    def _make_hash_value(self, value):
        """
        Creates a hashed value from the subscriber's data.
        """
        return salted_hmac("subscriber-token", value.encode('utf-8')).hexdigest()

    def check_token(self, subscriber, token):
        """
        Validates the token by comparing it to the generated token.
        """
        timestamp = str(subscriber.subscribed_at.timestamp())  # Use the subscription timestamp as part of the token
        value = f"{subscriber.pk}-{timestamp}"
        return token == self._make_hash_value(value)

# Create a global instance of the custom token generator
subscriber_token_generator = SubscriberTokenGenerator()
