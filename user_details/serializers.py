import logging
# from django.contrib.auth.models import User
from user_details.models import User
from rest_framework import serializers

logger = logging.getLogger(__name__)

''' Base Model Serializer for AuditTimestampModel columns'''
class BaseModelSerializer(serializers.ModelSerializer):
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

class UserSerializers(BaseModelSerializer):
    ''' User Serializers  '''
    first_name = serializers.SerializerMethodField(read_only=True)
    last_name = serializers.SerializerMethodField(read_only=True)
    full_name = serializers.SerializerMethodField(read_only=True)
    email = serializers.SerializerMethodField(read_only=True)
    phone_no = serializers.SerializerMethodField(read_only=True)
    password =  serializers.SerializerMethodField(read_only=True)
    user_type_id = serializers.SerializerMethodField(read_only=True)
    user_type =  serializers.SerializerMethodField(read_only=True)
    user_control = serializers.SerializerMethodField(read_only=True)

    def get_first_name(self,obj):
        ''' get first name '''
        try :
            UserSerializers.get_first_name.first_name = None
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_first_name.first_name 
  
    def get_last_name(self,obj):
        ''' get last name '''
        try :
            UserSerializers.get_last_name.last_name = None
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_last_name.last_name 
        
    def get_email(self,obj):
        ''' get email name '''
        try :
            UserSerializers.get_email.email = None
        except Exception as ex:
            logger.info(ex)
        return UserSerializers.get_email.email 


    