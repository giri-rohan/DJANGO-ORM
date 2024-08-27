import logging
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from user_details.serializers import (
    SignUpSerializer,GenerateOtpSerializer)
from user_details.models import User,UserOtp
from rest_framework.response import Response
from rest_framework import status, filters
from django.db import transaction
from django.db import connection
from django.utils import timezone
# Create your views here.
logger = logging.getLogger(__name__)


''' Create User API '''
class CreateUser(APIView):
    ''' Register User '''
    permission_classes = (AllowAny,)

    @swagger_auto_schema(tags=['User'], operation_description="Create User", operation_summary="User Create", request_body=SignUpSerializer)
    @transaction.atomic
    def post(self, request):
        ''' Register User '''
        logger.info("User Create Request Data : %s", request.data)
        request_data = request.data
        current_user = request.user
        response = {}
        http_status = None
        try:
            serializer = SignUpSerializer(data=request_data)
            if serializer.is_valid():
                user_data = {
                    "phone_number": request_data['phone_number'],
                    "password": request_data['password'],
                    "first_name": request_data['first_name'],
                    "last_name": request_data['last_name'],
                    "email": request_data['email'],
                    "user_type_id" : 1
                }
                user_instance = User.objects.create(**user_data)
                logger.info("User Instance : %s", user_instance.id)
                # user_details = {
                #     "user": user_instance,
                #     "phone": request_data['phone'],
                #     "user_type_id": request_data['user_type'],
                #     "organization_id": request_data['organization'],
                #     "created_by": current_user.id
                # }
                # UserDetails.objects.create(**user_details)
                # response["message"] = "User Created Successfully"
                # http_status = status.HTTP_201_CREATED
                # try:
                #     message = f"Hi {user_data['username']}, your login has been created with password {user_data['password']}."
                #     msg = EmailMessage()
                #     msg.set_content(message)
                #     msg['Subject'] = 'New User Creation'
                #     msg['From'] = settings.EMAIL_HOST_USER
                #     msg['To'] = user_data['email']

                #     # # Login
                #     # s =server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                #     # s.starttls()
                #     # s.login(settings.EMAIL_HOST_USER,settings.EMAIL_HOST_PASSWORD)

                #     # Sending the message
                #     s.send_message(msg)
                #     s.quit()
                # except Exception as exp:
                #     logger.exception("User Mail Sending Exception : %s", exp) 
            else:
                logger.info("Serializer Error : %s", serializer.errors)
                error_message = serializer_error_format(serializer.errors)
                response["errors"] = error_message
                http_status = status.HTTP_400_BAD_REQUEST

            return Response(
                response,
                status=http_status
            )
        except Exception as exp:
            logger.exception("User Create Exception : %s", exp)
            response['errors'] = "Server Error"
            http_status = status.HTTP_400_BAD_REQUEST
            return Response(
                response,
                status=http_status
            )
''' Generate OTP API '''
class GenerateOtp(APIView):
    permission_classes = (AllowAny,)
    @swagger_auto_schema(tags=['GenerateOtp'], operation_description="Generate Otp", operation_summary="Generate Otp Successfully", request_body=GenerateOtpSerializer)
    @transaction.atomic
    def post(self, request):
        email = request.data.get('u_email')
        logger.info(email)
        
        if User.objects.filter(email=email).exists():
            return Response({'warning': 'User Already Exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        if UserOtp.objects.filter(u_email=email).exists():
            logger.info(f"found mail {email}")
            user = UserOtp.objects.filter(u_email=email).order_by('-created_on').first()
            current_time = timezone.now()
            logger.info(f"Current time => {current_time}")
            if user.expire_time >= current_time:
                return Response({'warning': 'User OTP Generated After 10 minutes'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = GenerateOtpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'OTP generated and sent'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

""" Error Serializers [need to improve]"""
def serializer_error_format(error):
    ''' Serializer Error Format '''
    error_message = None
    if error.get('non_field_errors'):
        error_message = error['non_field_errors'][0]
    elif error.get('email'):
        error_message = error['email'][0]
    elif error.get('user_type'):
        error_message = error['user_type'][0]
    return error_message