from django.urls import path
from blogs.views import * 

app_name = 'blogs'

urlpatterns = [
# path('blog', blog, name='blog'),
path('api/blogs/', BlogGridApiView.as_view(), name='blogGridApi'),
path('api/blog/<slug:slug>/', BlogDetailsApiView.as_view(), name='blogDetailsApi'),
path('api/follow-us/', FollowUsAPI.as_view(), name='api-follow-us'),
path('', blogGrid, name='blogGrid'),
path('blog/<slug:slug>/', blogDetails, name='blogDetails'),
path('<str:category>/', blogGrid, name='blogGridCategory'),
path('page/<int:page>/', blogGrid, name='blogGridPage'),
path('<slug:slug>/<str:category>/', blogDetails, name='blogDetailsCategory'),

]