from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('register/',views.RegisterView.as_view(), name='register'),
    path('login/',views.LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view()),
    path('home/', views.HomeView.as_view(), name='userHome'),
    path('profile/',views.UserProfileView.as_view(), name='userProfile')

]
