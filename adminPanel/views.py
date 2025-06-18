from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny,IsAdminUser,IsAuthenticated
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from users.serializers import UserSerializer  # Adjust path if needed
import os
from django.conf import settings

User = get_user_model()

class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_staff and not user.isAdmin:
            return Response({'error': 'You are not authorized to access this panel.'}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        response = Response({
            'user': UserSerializer(user).data,
            'message': 'Admin login successful',
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key='access_token',
            value=str(access),
            secure=False,
            samesite='Lax',
            max_age=int(os.getenv('access_token_expiry')),
            path='/'
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            secure=False,
            samesite='Lax',
            max_age=int(os.getenv('cookie_max_age')),
            path='/'
        )
        return response
    

class AdminUserListView(APIView):
    permission_classes = [IsAdminUser]
    def get(self,request):
        users = User.objects.filter(isAdmin=False)
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

class BlockUserView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            # Don't allow blocking admins
            if user.isAdmin or user.is_staff:
                return Response(
                    {'error': 'Cannot block admin users'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            user.is_blocked = True
            # When a user is blocked, they should also be inactive
            user.is_active = False
            user.save()
            
            return Response({
                'message': f'User {user.email} has been blocked',
                'user': UserSerializer(user).data
            })
            
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

class UnblockUserView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.is_blocked = False
            # When unblocking, reactivate the account
            user.is_active = True
            user.save()
            
            return Response({
                'message': f'User {user.email} has been unblocked',
                'user': UserSerializer(user).data
            })
            
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )



class AdminLogoutView(APIView):
    permission_classes = [IsAdminUser]
    def post(self,request):
        response = Response({'message' : 'Logged out succesffully'}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token', path='/')
        response.delete_cookie('refresh_token', path='/')
        return response
