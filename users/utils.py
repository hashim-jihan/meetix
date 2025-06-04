from django.core.mail import send_mail
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def sendOtp(email, otp):
    subject = 'Your Email Verification Code'
    message = f'Your OTP code is {otp}. It expires in 1 minute.'
    from_email = 'ibadiperfumes111@gmail.com'
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)
