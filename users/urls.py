from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('register/',views.RegisterView.as_view(), name='register'),
    path('verify-otp/',views.VerifyOtpView.as_view(), name='verify-otp'),
    path('resend-otp/',views.ResendOtpView.as_view(), name='resend_otp'),
    path('login/',views.LoginView.as_view(), name='login'),
    path('google-auth/',views.GoogleAuthView.as_view(), name='google-auth'),
    path('token/refresh/', TokenRefreshView.as_view()),
    path('home/', views.HomeView.as_view(), name='userHome'),
    path('profile/',views.UserProfileView.as_view(), name='userProfile')

]
