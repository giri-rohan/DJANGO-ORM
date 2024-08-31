# # import jwt
# # from django.conf import settings
# # from django.http import JsonResponse
# # from rest_framework.authentication import get_authorization_header
# # from datetime import datetime, timedelta
# # from user_details.models import UserToken
# # from .utils import generate_refresh_token
# # import logging
# # logger = logging.getLogger(__name__)

# # class AuthMiddleware:
# #     def __init__(self, get_response):
# #         self.get_response = get_response
    
# #     def __call__(self, request):
# #         auth_response = self.authenticate(request)
# #         if auth_response is True:
# #             return self.get_response(request)
# #         else:
# #             return JsonResponse(auth_response, status=auth_response['code'])
    
# #     def authenticate(self, request):
# #         token = self.get_token(request)
# #         logger.info("===start===")
# #         # if not token:
# #         #     return {'code': 401, 'message': 'Authorization header missing or invalid'}

# #         try:
# #             payload = self.decode_token(token)
# #             user_id = payload.get('user_id')
# #             user_type = payload.get('user_type')
# #             exp = payload.get('exp')
            
# #             if not self.is_token_valid(exp):
# #                 new_token = generate_refresh_token(token)
# #                 return {'code': 408, 'message': 'Token expired, new token generated', 'token': new_token}
            
# #             user_token = UserToken.objects.get(user_id=user_id, user_type=user_type)
# #             if token != user_token.token:
# #                 return {'code': 403, 'message': 'Token mismatch'}
            
# #             return True
# #         except jwt.ExpiredSignatureError:
# #             return {'code': 403, 'message': 'Token expired'}
# #         except jwt.InvalidTokenError:
# #             return {'code': 403, 'message': 'Invalid token'}
# #         except Exception as e:
# #             return {'code': 500, 'message': 'Internal server error', 'error': str(e)}
    
# #     def get_token(self, request):
# #         auth_header = get_authorization_header(request).decode('utf-8')
# #         if auth_header and auth_header.startswith('Bearer '):
# #             return auth_header.split(' ')[1]
# #         return None

# #     def decode_token(self, token):
# #         return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

# #     def is_token_valid(self, exp):
# #         return datetime.utcnow() < datetime.utcfromtimestamp(exp)



from django.contrib.auth.backends import BaseBackend
from rest_framework import status
from user_details.models import (UserToken)
from django.http import HttpResponse
from rest_framework.authentication import get_authorization_header
from django.db.models import Q
from datetime import datetime, timedelta
from .utils import *
import logging, jwt, json
from django.conf import settings

logger = logging.getLogger(__name__)

class AuthMiddleware(BaseBackend):
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # self.auth(request)
        auth_resp = self.auth(request)
        logger.info(f"Auth Response : {auth_resp}")
        
        # if (type(auth_resp) != bool) and (auth_resp is not None and auth_resp['code'] == 200):
        #     request.user_details = auth_resp
        #     logger.info(f"request = {request}")
        #     return self.get_response(request)
        
        # elif auth_resp == True:
        if auth_resp == True:
            return self.get_response(request)
        
        else:
            code = auth_resp['code']
            message = auth_resp['message']
            resp_data = None
            if code == 408:
                logger.info("<=========== Response Code 408 =========>")
                new_token = auth_resp['token']
                logger.info(f"New Auth Token : {new_token}")
                resp_data = {"message" : message, "token" : new_token}
                resp_data = json.dumps(resp_data)
            else:
                logger.info("<=========== Response Code 403 =============>")
                resp_data = {"message" : message}
                resp_data = json.dumps(resp_data)
            logger.info(f"Resp Data : {resp_data}")
            resp = HttpResponse(resp_data, status=code, content_type ="application/json")
            return resp

    def auth(self,request):
        logger.info(f"Request Path: {request.path}")
        if request.path not in exclusion_list:
            user_id = None
            login_as = None
            user_type = None
            token = None
            try:
                token = get_authorization_header(request).decode("utf-8")
                logger.info(f"Token received from client : {token}")
                
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                
                # payload = jwt.decode(token, key=secret, algorithms=algo)
                logger.warning(f"Token Decode Response : {payload}")
                
                user_id = payload.get('user_id')
                user_type = payload.get('user_type')
                first_name = payload.get('first_name')
                last_name = payload.get('last_name')
                email = payload.get('email')
                phone = payload.get('phone')
                iat = payload.get('updated_on')
                exp = payload.get('expiry_time')
                token_created_at = datetime.utcfromtimestamp(iat)
                logger.warning(f"Token Created Time : {token_created_at} {iat}")
                
                expiry_time = datetime.utcfromtimestamp(exp)
                logger.warning(f"Expire Time : {expiry_time}")
                
                # param_obj = AdmnParameters.objects.filter(Q(parameter_key="token_validation_time")).values()
                # logger.warning(f"Parameter Object : {param_obj}")
                
                val_time_delta = 10
                logger.warning(f"Validation Time Delta : {val_time_delta}")
                
                validation_time = expiry_time - timedelta(minutes=val_time_delta)
                logger.warning(f"Validation Time : {validation_time}")
                
                current_time = datetime.utcnow()
                logger.warning(f"Current Time : {current_time}")
                
                # userObj = UserToken.objects.get(user_id=user_id, login_as=login_as, user_type=user_type)
                userObj = UserToken.objects.get(user_id=user_id, user_type=user_type)

                if validation_time < current_time < expiry_time:
                    jwt_token = generateRefreshToken(token)
                    expired_response = {"code" : status.HTTP_408_REQUEST_TIMEOUT, "message" : "Refresh Token Generate", "token" : jwt_token}
                    return expired_response
                
                elif current_time > expiry_time:
                    logger.info("Token Expired")
                    expired_response = {"code" : status.HTTP_403_FORBIDDEN, "message" : "Token Expired"}
                    return expired_response
                
                else:
                    user_token = userObj.token
                    logger.info(f"DB Token : {user_token}")
                    logger.info(f"Token : {token}")
                    if token == user_token:
                        payload.get("token", user_token)
                        return True
                        # obj = {
                        #     "user_details": payload,
                        #     "code": status.HTTP_200_OK
                        # }
                        # return obj
                    else:
                        logger.info("Token Mismatch")
                        expired_response = {"code" : status.HTTP_403_FORBIDDEN, "message" : "Token Mismatch"}
                        return expired_response
            
            except jwt.DecodeError as d:
                logger.info("Token Decode Error")
                logger.error(d)
                expired_response = {"code" : status.HTTP_403_FORBIDDEN, "message" : "JWT Decode Error"}
                return expired_response
            
            except jwt.ExpiredSignatureError as x:
                logger.info("<================= Token is Expired ================>")
                logger.error(x)
                logger.info(f"Expired Token : {token}")
                expired_response = {"code" : status.HTTP_403_FORBIDDEN, "message" : "Token Time Out Error"}
                return expired_response
            
            except jwt.InvalidTokenError as i:
                logger.error(i)
                expired_response = {"code" : status.HTTP_403_FORBIDDEN, "message" : "Invalid Token Error"}
                return expired_response
                
            except Exception as e:
                logger.info("Generic Exception")
                logger.exception(e)
                expired_response = {"code" : status.HTTP_403_FORBIDDEN, "message" : "Generic Exception"}
                return expired_response
                
        else:
            return True

