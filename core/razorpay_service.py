import razorpay
from django.conf import settings

class RazorpayService:
    def __init__(self):
        self.client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

    def create_payment(self, amount, currency='INR', receipt=None, notes=None):
        try:
            payment_data = {
                "amount": int(amount * 100),  # amount in paise
                "currency": currency,
                "receipt": receipt,
                "notes": notes or {}
            }
            payment = self.client.order.create(data=payment_data)
            return payment
        except Exception as e:
            return None

    def verify_signature(self, payment_id, order_id, signature):
        try:
            self.client.utility.verify_payment_signature({
                'razorpay_payment_id': payment_id,
                'razorpay_order_id': order_id,
                'razorpay_signature': signature
            })
            return True
        except razorpay.errors.SignatureVerificationError:
            return False
