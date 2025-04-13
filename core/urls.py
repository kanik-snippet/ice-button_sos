from core.views import *
from django.urls import path
from rest_framework_simplejwt import views as jwt_views





# app_name = "core"

urlpatterns = [   
    

   path('',home,name='home'),
   path('login',login,name='login'),
   path('signup/',register,name='register'),
   path('forgot/',forgot,name='forgot'),
   path('reset-pass/<str:token>/',resetpass,name='resetpass'),
   path('dashboard/', dashboard, name='dashboard'),
   path('remote/', remote, name='remote'),
   path('ice/', pod, name='pod'),
   path('log/', log, name='log'),
   path('wifi/', wifi, name='wifi'),
   path('stream/', stream, name='stream'),
   path('profile/', profile, name='profile'),
   path('subscription/', subscription, name='subscription'),
   path('change_password/', change_password, name='changepass'),
   path('ice_detail/<int:device_id>/', pod_detail, name='pod_detail'),
   path('add-contact/', add_contact, name='add_contact'),
   path('evlogs/<int:event_id>/',     evlogs, name='evlogs'),
   path('subscription_txn/',subscription_txn,name='subscription_txn'),
   path('terms-and-conditions/', terms, name='terms'),
   path('terms-of-use/', termsOfuse, name='termsOfuse'),
   path('privacy-policy/', privacy, name='privacy'),
   path('sales-and-refund-policy/', salesandrefund, name='salesandrefund'),
   path('legal-information/', legalinfo, name='legalinfo'),
   path('order-now/', ordernow, name='ordernow'),
   path('tutorials/', tutorials, name='tutorials'),
   path('pricing-plans/', plan_pricing, name='plan_pricing'),
   path('case-study/', case_study, name='case_study'),
   path('how-it-works/', hiworks, name='hiworks'),
   path('user_invoice/<int:transaction_id>/', user_invoice_view, name='user_invoice'),
   path('notifications/', notifications, name='notifications'),
   path('live/<str:clean_mac>/', live, name='live'),

   path('test/', test, name='test'),

   path('unsubscribe/<uidb64>/<token>/',unsubscribe, name='unsubscribe'),




   
   path('<slug:slug>/', static_content_view, name='static_content'),


#    path("send-whatsapp/", send_message_view, name="send_whatsapp"),




   # api


   path('api/login/', LoginAPIView.as_view(), name='login-api'),
   path('api/logout/', CustomLogoutView.as_view(), name='logout-api'),
   path('api/plans/', PlanOverviewAPIView.as_view(), name='plan-overview-api'),
   path('api/static-content/<slug:slug>/', StaticContentDetailView.as_view(), name='api_static_content'),
   path('api/password-reset-request/', PasswordResetRequestAPIView.as_view(), name='password-reset-requestapi-api'),
#    path('api/reset-pass/<str:token>/', PasswordResetConfirmAPIView.as_view(), name='reset-pass-api'),
   path('api/password-reset-confirm/<str:token>/', PasswordResetConfirmAPIView.as_view(), name='password-reset-confirm-api'),
   path('password-reset/<str:token>/', PasswordResetAPIView.as_view(), name='password-reset-api'),


   path('api/register/', UserRegistrationAPIView.as_view(), name='register-api'),
   path('api/verify-email/<str:uidb64>/<str:token>/', VerifyEmailAPIView.as_view(), name='verify-email-api'),
   path('api/dashboard/',DashboardAPIView.as_view(), name='user-dashboard-api'),
   path('api/register-device/', RegisterDeviceAPIView.as_view(), name='register-device-api'),
   path('api/user-device-list/',DeviceListView.as_view(), name='device-list-api'),
   path('api/device/<int:device_id>/', DeviceDetailView.as_view(), name='device-detail-api'),
   path('api/device/<int:device_id>/update/', DeviceUpdateView.as_view(), name='device-update-api'),
   path('api/device/<int:device_id>/delete/', DeviceDeleteView.as_view(), name='device-delete-api'),
   path('api/device/toggle-status/<int:device_id>/', ToggleDeviceStatusView.as_view(), name='toggle-device-status-api'),



   path('api/add-sos-contacts/', AddSOSContactsView.as_view(), name='add-sos-contacts-api'),
   path('api/sos-contacts/', SOSContactListView.as_view(), name='sos-contacts-api'),
   path('api/sos-contacts/<str:contact_reference>/', UpdateSOSContactsView.as_view(), name='update-sos-contact'),
   path('api/assign_contacts_to_device/', AssignContactToDeviceAPIView.as_view(), name='assign-contacts-to-device-api'),
   path('api/remove-contact-from-device/', RemoveContactFromDeviceAPIView.as_view(), name='remove_contact_from_device-api'),
   path('api/delete-sos-contact/', DeleteSOSContactView.as_view(), name='delete-sos-contact-api'),
   # path('delete-sos-email/<int:SOSEmails_id>/', DeleteSOSEmailAPIView.as_view(), name='delete-sos-email'),
   # path('delete-sos-phone/<int:SOSPhones_id>/', DeleteSOSPhoneAPIView.as_view(), name='delete-sos-phone'),
   path('api/resend-verification-email/', ResendVerificationEmailView.as_view(), name='resend-verification-email-api'),
   path('api/resend-verification-sms/', ResendVerificationSMSView.as_view(), name='resend-vrification-sms-api'),
   path('api/verify-sos-email/<str:uidb64>/<str:token>/', VerifySOSEmailView.as_view(), name='verify-sos-email-api'),
   path('api/verify-phone/<str:uidb64>/<str:token>/', VerifyPhoneAPIView.as_view(), name='verify-number-api'),
   
   
   path('api/profile/',GetProfileAPIView.as_view(), name='profile-api'),
   path('api/profile/update/',UpdateProfileAPIView.as_view(), name='update-profile-api'),
   path('api/update-profile-image/', UpdateProfileImageAPIView.as_view(), name='update-profile-image'),
   path('api/change-password/',ChangePasswordAPIView.as_view(), name='change-password-api'),
   path('api/check-stream/', CheckStreamAPIView.as_view(), name='check-stream'),



   path('api/event-logs/', EventListAPIView.as_view(), name='event-list-api'),
   path('api/notifications/event/<str:event_id>/', NotificationLogsAPIView.as_view(), name='notification-logs-api'),
   path('api/user/logs/', UserLogDetailView.as_view(), name='user_log_detail'),
   path('api/user-logs/<int:pk>/', UserLogDetailAPIView.as_view(), name='user-log-detail'),

   path('api/videos/', VideoListView.as_view(), name='video-list-api'),
   path('api/view-video/<int:video_id>/', ViewVideoAPIView.as_view(), name='view-video-api'),
   path('api/delete-video/<int:video_id>/', DeleteVideoAPIView.as_view(), name='delete-video-api'),



   path('api/connect-wifi/', ConnectWifiAPIView.as_view(), name='connect-wifi-api'),
   path('api/create-device-stream/', DeviceStreamKeyAPI.as_view(), name='create_device_stream'),
   path('api/get-stream/', GetStreamAPIView.as_view(), name='get-stream-api'),
#    path("api/send-whatsapp/", SendMessageView.as_view(), name="send_whatsapp_api"),


   path('api/create-order/', CreateOrderView.as_view(), name='create_order-api'),
   path('api/payment/callback/', PaymentCallbackView.as_view(), name='payment_callback-api'),
   path('api/transactions/', TransactionDetailsView.as_view(), name='transaction-details-api'),
   path('api/transactions/<int:pk>/', TransactionDetailView.as_view(), name='transaction-detail'),
   # path('transactions/', UserPaymentHistoryView.as_view(), name='user-payment-history'),
   path('api/faqs/', FAQListView.as_view(), name='faq-list'),
   path('api/order/', ContactUsAPIView.as_view(), name='contact_api'),
   path('api/get-in-touch/', GetInTouchAPIView.as_view(), name='get_in_touch'),
   path('api/subscribe/', SubscribeView.as_view(), name='subscribe'),


   # Api for RPi
   path('api/get-device-by-mac/', GetDeviceByMacAddressView.as_view(), name='get-device-by-mac-api'),
   path('api/notification-logs/', NotificationLogCreateView.as_view(), name='notification-log-create-api'),
   path('api/upload-video/', DeviceVideoUploadView.as_view(), name='upload-video-api'),
   path('api/answer/', AnswerCallView.as_view(), name='answer-call-api'),



   path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
   path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),


   #Api for smart watch
   path('api/sos-trigger/', SOSTriggerView.as_view(), name='sos-trigger'),

] 