from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from user_details.serializers import (
    SignUpSerializer)
from rest_framework.response import Response
from rest_framework import status, filters
from django.db import transaction
from django.db import connection
# Create your views here.



class CreateUser(APIView):
    ''' Register User '''
    permission_classes = (IsAuthenticated,)

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
                    "username": request_data['username'],
                    "password": request_data['password'],
                    "first_name": request_data['first_name'],
                    "last_name": request_data['last_name'],
                    "email": request_data['email']
                }
                user_instance = User.objects.create_user(**user_data)
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
