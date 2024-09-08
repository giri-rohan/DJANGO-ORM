"""
## generaterefreshtoken funcion which is generate refresh token 
## generatenewtoken function which is generate firsttime token 

"""
import logging
import jwt
from django.db import transaction
from datetime import datetime, timedelta
from user_details.models import UserToken
from django.conf import settings
from django.utils import timezone  

logger = logging.getLogger(__name__)

''' generaterefreshtoken func'''
def generaterefreshtoken(token):
    try:
        with transaction.atomic():
            secret_key = str(settings.JWT_SECRET_KEY)
            algorithm = str(settings.JWT_ALGORITHM)
            #Expire Time Define#
            expire_time_delta = 60
            exp_time = timezone.now() + timedelta(minutes=expire_time_delta)  # Use timezone.now()
            # Create new payload
            payload = jwt.decode(token, key=secret_key, algorithms=algorithm)

            user_id = payload.get('user_id')
            user_type = payload.get('user_type')
            first_name = payload.get('first_name')
            last_name = payload.get('last_name')
            email = payload.get('email')
            phone = payload.get('phone')
            expiry_time = payload.get('expiry_time')
            
            new_payload = {
                "user_id": user_id,
                "first_name": first_name,
                "user_type": user_type,
                "last_name": last_name,
                "phone_number": phone,
                "expiry_time": exp_time.timestamp(),
                "updated_on": timezone.now().timestamp()  # Use timezone.now()
            }
            logger.info(new_payload)
            

            # Encode new JWT token
            jwt_token = jwt.encode(payload=new_payload, key=secret_key, algorithm=algorithm)
            jwt_token = jwt_token.decode('utf-8')
            logger.info(jwt_token)
            
            # Update or create UserToken entry
            token_data = {
                "token": jwt_token,
                "expiry_time": exp_time.strftime('%Y-%m-%dT%H:%M:%S'),
                "updated_on": timezone.now().strftime('%Y-%m-%dT%H:%M:%S'),
                "allow_flag": 1
            }
            
            UserToken.objects.update_or_create(user_id=user_id, user_type=user_type, defaults=token_data)
            logger.info(f"Refresh token {'updated' if UserToken.objects.filter(user_id=user_id, user_type=user_type).exists() else 'created'} for User Type -- {user_type}")
            
            return jwt_token

    except jwt.ExpiredSignatureError as e:
        logger.error(f"Token expired: {e}")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
    except Exception as e:
        logger.exception("Error generating refresh token: %s", e)
    
    return None

''' generatenewtoken func'''
def generatenewtoken(id, user_type, first_name, last_name, email, phone):
    try:
        with transaction.atomic():
            # Determine token expiration based on user type
            expire_time_delta = 60
            exp_time = timezone.now() + timedelta(minutes=expire_time_delta)  # Use timezone.now()
            # Create new payload
            new_payload = {
                "user_id": id,
                "first_name": first_name,
                "user_type": user_type,
                "last_name": last_name,
                "phone_number": phone,
                "expiry_time": exp_time.timestamp(),
                "updated_on": timezone.now().timestamp()  # Use timezone.now()
            }
            logger.info(new_payload)
            secret_key = str(settings.JWT_SECRET_KEY)
            algorithm = str(settings.JWT_ALGORITHM)
            logger.info(algorithm)

            # Encode new JWT token
            jwt_token = jwt.encode(payload=new_payload, key=secret_key, algorithm=algorithm)
            jwt_token = jwt_token.decode('utf-8')
            logger.info(jwt_token)
            
            token_id_exists = UserToken.objects.filter(user_id=id, user_type=user_type).exists()
        
            if token_id_exists:
                token_obj = UserToken.objects.get(user_id=id, user_type=user_type)
                token_id = token_obj.token_id
                logger.info(token_id)
                token_update_data = {
                    "token": jwt_token,
                    "expiry_time": exp_time.strftime('%Y-%m-%dT%H:%M:%S'),
                    "updated_on": timezone.now().strftime('%Y-%m-%dT%H:%M:%S'),
                    "allow_flag": 1
                }
                UserToken.objects.filter(token_id=token_id).update(**token_update_data)
            else:
                # Create UserToken entry
                UserToken.objects.create(
                    user_id=id,
                    user_type=user_type,
                    token=jwt_token,
                    expiry_time=exp_time.strftime('%Y-%m-%d %H:%M:%S'),
                    updated_on=timezone.now().strftime('%Y-%m-%d %H:%M:%S')
                )
                logger.info(f"Refresh token {'updated' if UserToken.objects.filter(user_id=id, user_type=user_type).exists() else 'created'} for User Type -- {user_type}")
            
            return jwt_token

    except jwt.ExpiredSignatureError as e:
        logger.error(f"Token expired: {e}")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
    except Exception as e:
        logger.exception("Error generating refresh token: %s", e)
    
    return None

#! ''' Exclusion API List ''' #!
exclusion_list = [
    '/swagger/',
    '/orm/user/login/',
    '/orm/user/create/',
    '/orm/user/generateotp/',
]