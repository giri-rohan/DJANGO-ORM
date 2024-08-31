import logging
import jwt
from django.db import transaction
from datetime import datetime, timedelta
from user_details.models import UserToken
from django.conf import settings

# from constants import DB_STRF_TIME

logger = logging.getLogger(__name__)

def generaterefreshtoken(token):
    try:
        with transaction.atomic():
            # Fetch JWT parameters
            # parameters = CmoParameterMaster.objects.filter(Q(parameter_key="jwt_algo") | Q(parameter_key="jwt_secret")).values_list('parameter_key', 'parameter_value')
            payload = jwt.decode(access_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
            # params_dict = dict(parameters)
            # algo = params_dict.get("jwt_algo")
            # secret = params_dict.get("jwt_secret")
            
            # Decode the existing token
            # payload = jwt.decode(token, key=secret, algorithms=algo)
            user_id = payload.get('user_id')
            user_type = payload.get('user_type')
            first_name = payload.get('first_name')
            last_name = payload.get('last_name')
            email = payload.get('email')
            phone = payload.get('phone')
            
            # Determine token expiration based on user type
            expire_key = "token_expire_time" if user_type == 1 else "bsk_token_expire_time"
            expire_time_delta = 10
            exp_time = datetime.utcnow() + timedelta(minutes=expire_time_delta) if user_type == 1 else datetime.utcnow() + timedelta(days=expire_time_delta)
            
            # Create new payload
            payload = {
                "user_id": user_id,
                "first_name": first_name,
                "user_type": user_type,
                "last_name": last_name,
                "phone_number": phone,
                "expiry_time": exp_time,
                "updated_on": datetime.utcnow()
            }
            
            # Encode new JWT token
            jwt_token = jwt.encode(payload=payload, key=secret, algorithm=algo)
            
            # Update or create UserToken entry
            token_data = {
                "token": jwt_token,
                "expiry_time": exp_time.strftime(DB_STRF_TIME),
                "updated_on": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
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


def generatenewtoken(id,user_type,first_name,last_name,email,phone):
    try:
        with transaction.atomic():
            # Fetch JWT parameters
            # parameters = CmoParameterMaster.objects.filter(Q(parameter_key="jwt_algo") | Q(parameter_key="jwt_secret")).values_list('parameter_key', 'parameter_value')
            # payload = jwt.decode(access_token, settings.JWT_ACCESS_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
            # # params_dict = dict(parameters)
            # # algo = params_dict.get("jwt_algo")
            # # secret = params_dict.get("jwt_secret")
            
            # # Decode the existing token
            # # payload = jwt.decode(token, key=secret, algorithms=algo)
            # user_id = payload.get('user_id')
            # user_type = payload.get('user_type')
            # first_name = payload.get('first_name')
            # last_name = payload.get('last_name')
            # email = payload.get('email')
            # phone = payload.get('phone')
            logger.info(first_name)
            # # Determine token expiration based on user type
            # expire_key = "token_expire_time" if user_type == 1 else "bsk_token_expire_time"
            expire_time_delta = 1
            exp_time = datetime.utcnow() + timedelta(minutes=expire_time_delta) 
            # Create new payload
            new_payload = {
                "user_id": id,
                "first_name": first_name,
                "user_type": user_type,
                "last_name": last_name,
                "phone_number": phone,
                "expiry_time": exp_time.timestamp(),
                "updated_on": datetime.utcnow().timestamp()
            }
            logger.info(new_payload)
            # Encode new JWT token
            jwt_token = jwt.encode(payload=new_payload,key = settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
            logger.info(jwt_token)
            token_id_exists = UserToken.objects.filter(user_id=id,user_type=user_type).exists()
        
            if token_id_exists:
                token_obj = UserToken.objects.get(user_id=id,user_type=user_type)
                token_id = token_obj.token_id
                logger.info(token_id)
                token_update_data = {"token":jwt_token, "expiry_time":exp_time.strftime('%Y-%m-%dT%H:%M:%S'), "updated_on":datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'), "allow_flag":1}
                UserToken.objects.filter(token_id=token_id).update(**token_update_data)
            else:
            # create UserToken entry
                UserToken.objects.create(
                        user_id = id,
                        user_type = user_type,
                        token = jwt_token,
                        expiry_time = exp_time.strftime('%Y-%m-%d %H:%M:%S'),
                        updated_on = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                )
                # UserToken.objects.create(**new_payload)
                # UserToken.objects.update_or_create(user_id=user_id, user_type=user_type, defaults=token_data)
                logger.info(f"Refresh token {'updated' if UserToken.objects.filter(user_id=id, user_type=user_type).exists() else 'created'} for User Type -- {user_type}")
            
            return jwt_token

    except jwt.ExpiredSignatureError as e:
        logger.error(f"Token expired: {e}")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
    except Exception as e:
        logger.exception("Error generating refresh token: %s", e)
    
    return None
# Exclusion API List
exclusion_list = [
    '/cmosvc/health/',
    '/swagger/',
    '/orm/user/login/',
    '/cmosvc/user/generateotp/',
    '/cmosvc/user/login/',
    '/cmosvc/user/bskuserlogin/',
    '/cmosvc/user/unlockgrievances/',
    '/cmosvc/initiate/autoreturn/',
    '/cmosvc/admin/updategrievancependingdays/',
    '/cmosvc/admin/publicshowgrievancestatus/',
    '/cmosvc/dashboard/getdistwisegrievancecount/',
    '/cmosvc/dashboard/getdistwisegrievancecountfilter/',
    '/cmosvc/home/gethomepagecount/',
    '/cmosvc/home/getgrievancestaus/',
    '/cmosvc/home/refreshvisitorcount/',
    '/cmosvc/home/getrefreshvisitorcount/',
]
