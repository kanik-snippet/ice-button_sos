"""
URL configuration for panic_button project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.http import HttpResponse

schema_view = get_schema_view(
    openapi.Info(
        title="Ice-Button API",
        default_version='v1',
        description=(
            "The Ice-Button API is designed to provide seamless integration for emergency alert systems. "
            "It allows users to connect devices, manage contacts, and handle emergency notifications with ease. "
            "Key features include video uploads for events, SOS contact management, and real-time notifications."
        ),
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@yourapi.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)
def google_verification_file(request):
    content = "google-site-verification: google6592f66432678f8c.html"
    return HttpResponse(content, content_type="text/html")

urlpatterns = [
    path('dj-admin/', admin.site.urls),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    path('blogs/', include('blogs.urls')),
    path('', include('core.urls')),
    path('admin/', include('customadmin.urls')),
    path("google6592f66432678f8c.html", google_verification_file, name="google-site-verification"),
    path('i18n/', include('django.conf.urls.i18n')),  # Add this line for language switching

    # Swagger URLs

] 

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)