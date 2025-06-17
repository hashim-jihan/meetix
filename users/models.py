from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from datetime import timedelta
from django.conf import settings

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('User must have an email address')
        if not username:
            raise ValueError('user must have username')
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('isAdmin',True)
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_staff',True)
        return self.create_user(email, username, password, **extra_fields)




class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(max_length=100,unique=True)
    email = models.EmailField(unique=True)

    is_blocked = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    isAdmin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)


    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        db_table = 'users'

    def __str__(self):
        return self.email
    
    def isOtpExpired(self):
        if self.otp_created_at:
            return timezone.now() > self.otp_created_at + timedelta(minutes=1)
        return True



class UserDetails(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete = models.CASCADE,
        related_name = 'details',
        unique = True
    )
    full_name = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    mobile = models.CharField(max_length=15, blank=True)
    streak = models.IntegerField(default=0)
    challenge_point = models.IntegerField(default=0)
    is_premium = models.BooleanField(default=False)


    def __str__(self):
        return f'{self.user.username} details'
    
    class Meta:
        db_table = 'user_details'



