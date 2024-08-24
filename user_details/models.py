"""
## MODELS WITH SERIALIZERS ##
INHERIT FROM '''AuditTimestampModel''' FOR DATETIME
"""
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator

''' Audit Timestamp Models '''
class AuditTimestampModel(models.Model):
    created_by = models.IntegerField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_by = models.IntegerField(blank=True, null=True)
    updated_on = models.DateTimeField(auto_now=True)

    class Meta:
        ''' Meta Class '''
        abstract = True

''' User Details Model '''
class UserType(AuditTimestampModel):   
    user_type_id = models.BigAutoField("UserTypeId", primary_key=True)
    user_type_name = models.CharField(
        "UserTypeName", max_length=30, blank=True, null=True)
    user_control = models.JSONField("UserControlLogic", blank=True, null=True)

    class Meta:
        ''' Meta Class '''
        db_table = 'user_type'    

''' User Models '''
class User(AuditTimestampModel):
    id = models.BigAutoField(primary_key=True)
    first_name = models.CharField(max_length=50,blank=False,null=False)
    last_name = models.CharField(max_length=50,null=True,blank=True)
    phone_number = models.CharField(
        max_length=10,  
        validators=[
            RegexValidator(
                regex=r'^[6789]\d{9}$', 
                message='Phone number must start with 6, 7, 8, or 9 and be exactly equal to 10 digits '
            )
        ],
        blank=True,
        null=True,
        verbose_name="Phone Number")
    email = models.CharField(
        max_length=254,  
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', 
                message='Enter a valid email address.'
            )
        ],
        blank=False,
        null=False,
        verbose_name="Email Address"
    )
    user_type = models.ForeignKey(
        UserType, on_delete=models.CASCADE, help_text="User Type Id"
    )
    password = models.CharField(max_length=255, null=True, blank=False)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()

''' User Token Models '''
class UserToken(models.Model):
    token_id = models.BigAutoField(primary_key=True)
    user_id = models.BigIntegerField(blank=False,null=True)
    user_type = models.IntegerField(blank=False,null=True)
    token = models.CharField(max_length=255)
    updated_on = models.DateTimeField(blank=False,null=True)
    expiry_time = models.DateTimeField(blank=False,null=True)
    allow_flag = models.IntegerField(default=1,blank=False,null=True)

    class Meta:
        managed = True
        db_table = 'user_token'

''' User Type '''
class UserOtp(AuditTimestampModel):
    otp_id = models.BigAutoField(primary_key=True)
    u_phone = models.CharField(max_length=45, blank=True, null=True)
    u_email = models.CharField(max_length=100, blank=True, null=True)
    otp = models.CharField(max_length=7,blank=False,null=True)
    expire_time = models.DateTimeField(blank=False,null=True)
    
    class Meta:
        managed = True
        db_table = 'user_otp'