from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('register/',views.RegisterView.as_view(), name='register'),
    path('verify-otp/',views.VerifyOtpView.as_view(), name='verify-otp'),
    path('resend-otp/',views.ResendOtpView.as_view(), name='resend_otp'),
    path('login/',views.LoginView.as_view(), name='login'),
    path('google-auth/',views.GoogleAuthView.as_view(), name='google-auth'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('forgot-password/',views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/<uidb64>/<token>/',views.ResetPasswordView.as_view(), name='reset-password'),
    path('home/', views.HomeView.as_view(), name='userHome'),
    path('logout/',views.LogoutView.as_view(), name='logout'),
    path('profile/',views.UserProfileView.as_view(), name='userProfile'),
    path('update-profile/',views.UpdateProfileView.as_view(), name='update-profile')
]
