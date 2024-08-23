import logging
# from django.contrib.auth.models import User
from user_details.models import User
from rest_framework import serializers

logger = logging.getLogger(__name__)

class BaseModelSerializer(serializers.ModelSerializer):
    ''' Base Model Serializer for AuditTimestampModel columns'''
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

