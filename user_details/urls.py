''' user_details Views URL'''
from django.urls import path
from .views import  CreateUser,GenerateOtp,VerifyOtp
# VerifyOtpView

urlpatterns = [
    path('verifyotp/', VerifyOtp.as_view(), name='verify_otp'),
    path('create/', CreateUser.as_view(), name='signup'),
    path('generateotp/',GenerateOtp.as_view(), name='generate_otp'),
]