from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import generics,status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .utils import generate_otp, sendOtp
from .models import EmailOtp

User = get_user_model()


# Create your views here.
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
        # user.is_active = False
        user.save()

        return Response({'message' :'successfully registered'}, status=status.HTTP_201_CREATED)

        # otp = generate_otp()
        # print(otp)
        # EmailOtp.objects.create(user=user, otp=otp)
        # sendOtp(email, otp)
        # return Response({'message' : 'user registered. OTP sent to email'}, status=status.HTTP_201_CREATED)
    


# class VerifyOtpView(APIView):
#     permission_classes = [AllowAny]
#     def post(self,request):
#         email = request.data.get('email')
#         otp = request.data.get('otp')

#         try:
#             user = User.objects.get(email=email)
#             otpRecord = EmailOtp.objects.filter(user=user, otp=otp, is_verified=False).last()
            
#             if not otpRecord:
#                 return Response({'erorr': 'Invalid otp'}, status=status.HTTP_400_BAD_REQUEST)
            
#             if otpRecord.IsExpired():
#                 return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
            
#             otpRecord.is_verified = True
#             otpRecord.save()

#             user.is_active = True
#             user.is_verified = True
#             user.save()
#             return Response({'message' : 'Email verified successfully'}, status=status.HTTP_200_OK)
#         except User.DoesNotExist:
#             return Response({'error' : 'user not found'}, status=status.HTTP_404_NOT_FOUND)



    

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
        return Response({
            'user' : UserSerializer(user).data,
            'refresh' : str(refresh),
            'access' : str(refresh.access_token)
        },status=status.HTTP_200_OK)
    

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
    
    





