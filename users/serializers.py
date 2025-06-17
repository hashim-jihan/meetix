from rest_framework import serializers
from .models import User, UserDetails
import re



class UserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDetails
        fields = ['full_name', 'description','mobile', 'streak', 'challenge_point', 'is_premium']

        def validate_full_name(self, value):
            if len(value.strip()) < 5:
                raise serializers.ValidationError("Full name must be at least 5 characters long.")
            return value

        def validate_description(self, value):
            if value and len(value) > 20:
                raise serializers.ValidationError("Bio/description must not exceed 20 characters.")
            return value

        def validate_mobile(self, value):
            pattern = r'^[6-9]\d{9}$'  # Indian mobile numbers
            if not re.match(pattern, value):
                raise serializers.ValidationError("Enter a valid 10-digit Indian mobile number starting with 6-9.")
            return value




class UserSerializer(serializers.ModelSerializer):
    details = UserDetailsSerializer()
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'details']
        extra_kwargs = {
            'password' : {'write_only' : True}
        }

    def create(self,validated_data):
        return User.objects.create_user(
            username = validated_data['username'],
            email = validated_data['email'],
            password = validated_data['password']
        )






