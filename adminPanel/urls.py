from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('login/',views.AdminLoginView.as_view(), name='admin-login'),
    path('users/',views.AdminUserListView.as_view(), name='users'), 
    path('block/<str:user_id>/', views.BlockUserView.as_view(), name='block-user'),
    path('unblock/<str:user_id>/', views.UnblockUserView.as_view(), name='unblock-user'),
    path('admin-logout/',views.AdminLogoutView.as_view(), name='admin-logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
