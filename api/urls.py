from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

from api.views import *

urlpatterns = [
    path('sign-up', SignUpView.as_view(), name='user_sign_up'),
    path('sign-in', SignInView.as_view(), name='user_sign_in'),
    path('university', UniversityNameView.as_view(), name='university'),
    path('university/<int:pk>', UniversityNameRUDView.as_view(), name='university_details'),
    path('users/<int:pk>/profile', UserDetailView.as_view(), name='users_details'),
    path('category', CategoryView.as_view(), name='category'),
    path('category/<int:pk>', CategoryRUDView.as_view(), name='category_details'),
    path('post', PostView.as_view(), name='post'),
    path('post/<int:pk>', PostRUDView.as_view(), name='post_details'),
    path('event', EventView.as_view(), name='event'),
    path('event/<int:pk>', EventRUDView.as_view(), name='event_details'),

    # *****************************Aouth2.0 Authentications*************************
    path('token', Token.as_view(), name='token'),
    path('token/refresh', RefreshToken.as_view(), name='token_refresh'),
    path('token/revoke', RevokeToken.as_view(), name='token_revoke'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
