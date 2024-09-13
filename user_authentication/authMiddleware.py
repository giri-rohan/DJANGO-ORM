"""
##################### authMiddleware.py ##################
"""
from django.contrib.auth.backends import BaseBackend
from rest_framework import status
from user_details.models import UserToken
from django.http import JsonResponse
from rest_framework.authentication import get_authorization_header
from datetime import datetime, timedelta
from .utils import generaterefreshtoken,exclusion_list
import logging, jwt, json
from django.conf import settings

logger = logging.getLogger(__name__)
from django.utils import timezone
import jwt
from datetime import datetime, timedelta
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from django.http import JsonResponse
from user_details.models import UserToken
from .utils import generaterefreshtoken, exclusion_list
from django.urls import resolve
import logging

logger = logging.getLogger(__name__)

class AuthMiddleware(BaseBackend):
    def __init__(self, get_response):
        self.get_response = get_response
        logger.info(f"Initialized AuthMiddleware with get_response: {self.get_response}")

    def __call__(self, request):
        
        auth_resp = self.auth(request)
        logger.info(f"Auth Response : {auth_resp}")

        if auth_resp == True:
            return self.get_response(request)
        else:
            code = auth_resp['code']
            message = auth_resp['message']
            resp_data = {"message": message}

            if code == status.HTTP_408_REQUEST_TIMEOUT:
                logger.info("<=========== Response Code 408 =========>")
                new_token = auth_resp.get('token')
                logger.info(f"New Auth Token : {new_token}")
                resp_data['token'] = new_token

            logger.info(f"Response Data : {resp_data}")
            return JsonResponse(resp_data, status=code)

    def auth(self, request):
        logger.info(f"Request Path: {request.path}")

        if request.path not in exclusion_list:
            try:
                token_bearer = get_authorization_header(request).decode("utf-8")
                logger.info(f"Authorization Header: {token_bearer}")
                
                if not token_bearer.startswith("Bearer "):
                    logger.warning("Authorization header does not start with Bearer")
                    return {
                        "code": status.HTTP_401_UNAUTHORIZED,
                        "message": "Invalid Authorization Header"
                    }

                token = token_bearer.split(' ')[1]
                logger.info(f"Token received from client: {token}")

                secret_key = str(settings.JWT_SECRET_KEY)
                algorithm = str(settings.JWT_ALGORITHM)
                payload = jwt.decode(token, key=secret_key, algorithm=algorithm)
                logger.info(f"Token Decode Response: {payload}")

                user_id = payload.get('user_id')
                user_type = payload.get('user_type')
                first_name = payload.get('first_name')
                last_name = payload.get('last_name')
                email = payload.get('email')
                phone = payload.get('phone')
                iat = payload.get('updated_on')
                exp = payload.get('expiry_time')

                if not all([user_id, user_type, iat, exp]):
                    logger.warning("Missing fields in token payload")
                    return {
                        "code": status.HTTP_401_UNAUTHORIZED,
                        "message": "Invalid Token Payload"
                    }

                # Convert timestamps to naive datetime objects
                token_created_at_naive = datetime.utcfromtimestamp(iat)
                expiry_time_naive = datetime.utcfromtimestamp(exp)

                # Make datetime objects timezone-aware
                token_created_at = timezone.make_aware(token_created_at_naive, timezone.utc)
                expiry_time = timezone.make_aware(expiry_time_naive, timezone.utc)

                logger.info(f"Token Created Time: {token_created_at}")
                logger.info(f"Expire Time: {expiry_time}")

                val_time_delta = 10
                validation_time = expiry_time - timedelta(minutes=val_time_delta)
                current_time = timezone.now()

                logger.info(f"Current Time: {current_time}")
                logger.info(f"Validation Time: {validation_time}")

                user_obj = UserToken.objects.get(user_id=user_id, user_type=user_type)

                if validation_time < current_time < expiry_time:
                    jwt_token = generaterefreshtoken(token)
                    return {
                        "code": status.HTTP_408_REQUEST_TIMEOUT,
                        "message": "Refresh Token Generated",
                        "token": jwt_token
                    }
                
                elif current_time > expiry_time:
                    logger.info("Token Expired")
                    return {
                        "code": status.HTTP_403_FORBIDDEN,
                        "message": "Token Expired"
                    }
                
                else:
                    user_token = user_obj.token
                    if token == user_token:
                        logger.info("Token Valid")
                        return True
                    else:
                        logger.info("Token Mismatch")
                        return {
                            "code": status.HTTP_403_FORBIDDEN,
                            "message": "Token Mismatch"
                        }
            
            except jwt.ExpiredSignatureError:
                logger.info("Token Expired")
                return {
                    "code": status.HTTP_403_FORBIDDEN,
                    "message": "Token Expired"
                }
            
            except jwt.InvalidTokenError:
                logger.error("Invalid Token")
                return {
                    "code": status.HTTP_403_FORBIDDEN,
                    "message": "Invalid Token"
                }
                
            except Exception as e:
                logger.error("Generic Exception")
                logger.exception(e)
                return {
                    "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": "Internal Server Error"
                }
            
        else:
            return True
