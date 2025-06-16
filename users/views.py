from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .utils import generate_otp, sendOtp
from dotenv import load_dotenv
import os
from django.utils import timezone
import firebase_admin
from firebase_admin import auth as firebase_auth, credentials
from django.contrib.auth.hashers import make_password
import secrets


User = get_user_model()

if not firebase_admin._apps:
    cred = credentials.Certificate(os.getenv('FIREBASE_CREDENTIALS_PATH'))
    firebase_admin.initialize_app(cred)

# Create your views here.

class GoogleAuthView(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        id_token = request.data.get('id_token')
        

        if not id_token:
            return Response({'error': 'ID token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            email = decoded_token.get('email')
            username = decoded_token.get('name') or email.split('@')[0]

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
        except Exception as e:
            print(e)
            return Response({'error': 'Invalid or expired Firebase token'}, status=status.HTTP_401_UNAUTHORIZED)




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
            max_age=int(os.getenv('access_token_expiry'))
        )

        response.set_cookie(
            key = 'refresh_token',
            value = str(refresh),
            secure = False,
            samesite='Lax',
            max_age=int(os.getenv('cookie_max_age'))
        )
        return response





class HomeView(APIView):
    def get(self, request):
        user = request.user
        return Response({"message": f"{user.username}"})




class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    





