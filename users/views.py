from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer,UserDetailsSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .utils import generate_otp, sendOtp
from dotenv import load_dotenv
import os
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import secrets
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, smart_str, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings



User = get_user_model()

# Create your views here.

class GoogleAuthView(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        username = request.data.get('name')
        email = request.data.get('email')
        

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            password = secrets.token_urlsafe(12)
            user = User.objects.create_user(
                email = email,
                username = username,
                password = password                
            )
                
            user.is_verified = True
            user.save()

        if user.is_blocked:
            return Response({'error': 'User is blocked'}, status=status.HTTP_403_FORBIDDEN)
                
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        response = Response({
            'success' : True,
            'user' : UserSerializer(user).data,
            'message' : 'Successfully authenticated with Google'
        }, status=status.HTTP_200_OK)

            
        response.set_cookie(
            key='access_token',
            value=str(access),
            secure=False,
            samesite='Lax',
            max_age=int(os.getenv('access_token_expiry'))
            )

        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            secure=False,
            samesite='Lax',
            max_age=int(os.getenv('cookie_max_age'))
            )
        return response




class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        confirmPassword = request.data.get('confirmPassword')

        if password != confirmPassword:
            return Response({'errors' : 'passwords doest not match'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'errors' : 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        

        user = User.objects.create_user(username=username ,email=email, password=password)
        user.is_active = False

        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        sendOtp(user.email, otp)
        print(user.otp)
        return Response({'message' :'Otp sent to your email. verify your account'}, status=status.HTTP_201_CREATED)



class VerifyOtpView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        otp = request.data.get('otp')
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if user.is_verified:
            return Response({'message' : 'User is alreday verified'}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.otp != otp:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.isOtpExpired():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.is_verified = True
        user.is_active = True
        user.otp = None
        user.otp_created_at = None
        user.save()
        return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)



class ResendOtpView(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if user.is_verified:
            return Response({'message': 'User is already verified'}, status=status.HTTP_400_BAD_REQUEST)
        
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        sendOtp(email, otp)
        print(user.otp)
        return Response({'message' : 'Otp resent successfully'}, status=status.HTTP_200_OK)
    
    

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'errors' : "email and password are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.check_password(password):
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if user.is_blocked:
            return Response({'errors':'User is blocked'}, status=status.HTTP_403_FORBIDDEN)
        
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        response = Response({
            'user' : UserSerializer(user).data,
            'message' : 'Successfully loggedIn'
        },status=status.HTTP_200_OK)

        response.set_cookie(
            key = 'access_token',
            value = str(access),
            secure = False,
            samesite='Lax',
            max_age=int(os.getenv('access_token_expiry')),
            path='/'
        )

        response.set_cookie(
            key = 'refresh_token',
            value = str(refresh),
            secure = False,
            samesite='Lax',
            max_age=int(os.getenv('cookie_max_age')),
            path='/'
        )
        return response



class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_link = f'{settings.FRONTEND_URL}/reset-password/{uid}/{token}'
            print(reset_link)

            send_mail(
                subject='Reset your password',
                message=f'Click the link to reset your password: {reset_link}',
                from_email='ibadiperfumes111@gmail.com',
                recipient_list = [email]
            )
            return Response({'success': True, 'message' : 'Password reset link sent to your email'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'success' : False, 'message' : 'User with this mail does not exist'}, status=status.HTTP_400_BAD_REQUEST)




class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        password = request.data.get('password')
        try:
            uid = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Invalid or expired token'}, status=400)
            user.set_password(password)
            user.save()
            return Response({'success' : True, 'message':'Password has been reset successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'success' : False, 'message':'Something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
            



class HomeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        print('hello')
        return Response({"message": f"{user.username}"})



class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        print("hello")
        response = Response({'message' : 'Logged out succesffully'}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token', path='/')
        response.delete_cookie('refresh_token', path='/')
        return response



class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        user = request.user
        serializer = UserSerializer(user)
        print(serializer.data)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        user = request.user
        user_details = user.details
        data = request.data 

        user_data = {'username' : data.get('username')}
        details_data = data.get('details',{})

        user_serializer = UserSerializer(user, data=user_data, partial=True)
        details_serializer = UserDetailsSerializer(user_details, data=details_data, partial=True)

        if user_serializer.is_valid() and details_serializer.is_valid():
            user_serializer.save()
            details_serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_200_OK)
        else:
            return Response({
                "user_errors": user_serializer.errors,
                "details_errors": details_serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    





