from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import generics,status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate

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
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

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
    
    





