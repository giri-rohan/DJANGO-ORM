import logging
# from django.contrib.auth.models import User
from user_details.models import User,UserType,UserOtp,UserToken
from rest_framework import serializers
import random
from django.utils import timezone

logger = logging.getLogger(__name__)


class BaseModelSerializer(serializers.ModelSerializer):
    ''' Base Model Serializer for AuditTimestampModel columns '''
    created_by_name = serializers.SerializerMethodField(read_only=True)
    updated_by_name = serializers.SerializerMethodField(read_only=True)

    def get_created_by_name(self, obj):
        ''' Created By User Name '''
        if obj.created_by:
            name = User.objects.get(id=obj.created_by).get_full_name()
            return name
        return None

    def get_updated_by_name(self, obj):
        ''' Updated By User Name'''
        if obj.updated_by:
            name = User.objects.get(id=obj.updated_by).get_full_name()
            return name
        return None

class UserTypeSerializer(serializers.ModelSerializer):
    ''' UserType Serializer '''
    class Meta:
        ''' Meta Class '''
        model = UserType
        fields = '__all__'

class UserSerializers(BaseModelSerializer):
    ''' User Serializers  '''
    first_name = serializers.SerializerMethodField(read_only=True)
    last_name = serializers.SerializerMethodField(read_only=True)
    full_name = serializers.SerializerMethodField(read_only=True)
    email = serializers.SerializerMethodField(read_only=True)
    phone_number = serializers.SerializerMethodField(read_only=True)
    # password =  serializers.SerializerMethodField(read_only=True)
    user_type_id = serializers.SerializerMethodField(read_only=True)
    user_type =  serializers.SerializerMethodField(read_only=True)
    user_control = serializers.SerializerMethodField(read_only=True)

    def get_first_name(self,obj):
        ''' get first name '''
        UserSerializers.get_first_name.first_name = None
        try :
            UserSerializers.get_first_name.first_name = obj.first_name
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_first_name.first_name 
  
    def get_last_name(self,obj):
        ''' get last name '''
        UserSerializers.get_last_name.last_name = None
        try :
            UserSerializers.get_last_name.last_name = obj.last_name
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_last_name.last_name 
        
    def get_email(self,obj):
        ''' get email name '''
        UserSerializers.get_email.email = None
        try :
            UserSerializers.get_email.email = obj.email
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_email.email 

    def get_full_name(self,obj):
        ''' get full name '''
        UserSerializers.get_full_name.full_name = None
        try :
            UserSerializers.get_full_name.full_name = obj.user.get_full_name()
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_full_name.full_name 

    def get_phone_number(self,obj):
        ''' get phone no'''
        UserSerializers.get_phone_number.phone_number = None
        try :
            UserSerializers.get_phone_number.phone_number = obj.phone_number
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_phone_number.phone_number

    
    def get_user_type(self,obj):
        ''' get user type '''
        UserSerializers.get_user_type.user_type = None
        try :
            UserSerializers.get_user_type.user_type = obj.user_type_name
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_user_type.user_type 

class SignUpSerializer(serializers.Serializer):
    ''' Sign Up Serializer '''
    # username = serializers.CharField(
    #     max_length=255, min_length=5, allow_blank=False)
    password = serializers.CharField(
        max_length=150, min_length=8, allow_blank=False)
    # confirm_password = serializers.CharField(
    #     max_length=150, min_length=8, allow_blank=False)
    email = serializers.EmailField(
        max_length=150, allow_blank=False)
    first_name = serializers.CharField(
        max_length=150, allow_blank=False)
    last_name = serializers.CharField(
        max_length=150, allow_blank=False)
    phone_number = serializers.CharField(
        max_length=150, min_length=8, allow_blank=False)
    user_type = serializers.IntegerField()


    def validate(self, data):
        # Retrieve the password and confirm_password fields from the data
        # user_obj = User.objects.filter(username=data.get('username'))
        # if user_obj.exists():
        #     raise ValidationError("User already exists")
        #!! NEED TO IMPROVE CONDITION YOU DB CALL IN VIEWS !!#
        if User.objects.filter(email=data.get('email')).exists():
            raise ValidationError("User email already exists")

        password = data.get('password')

        # Check if the passwords < 8
        if len(password) < 8:
            raise ValidationError("Passwords should be greater and equal 8 .")
        return data    

class GenerateOtpSerializer(serializers.Serializer):
    u_email = serializers.EmailField()

    def create(self, validated_data):
        u_email = validated_data['u_email']
        otp = f"{random.randint(100000, 999999)}"
        u_phone = "9999999999"
        logger.info(otp)
        expire_time = timezone.now() + timezone.timedelta(minutes=1)

        UserOtp.objects.create(u_email=u_email,u_phone=u_phone,
            otp=otp, expire_time=expire_time,
        )
        return {"otp": otp}

class VerifyOtpSerializer(serializers.Serializer):
    otp = serializers.IntegerField(required=True)
    u_email = serializers.EmailField()

    def validate(self,data):
        user_otp = data.get('otp')
        logger.info(f"LENGTH=> {user_otp}")
        if user_otp < 100000 or user_otp > 999999:
            raise serializers.ValidationError("OTP must be a 6-digit number.")
        return data
        
