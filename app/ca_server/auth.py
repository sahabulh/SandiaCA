from fastapi import HTTPException, Depends
from fastapi.security import APIKeyHeader

# Define API keys
full_access_key = ['iamdev','iamadmin']
user_access_key = ['iamuser']

# You would use as an environment var in real life
X_API_KEY = APIKeyHeader(name='X-API-Key')

def api_key_auth(x_api_key: str = Depends(X_API_KEY)):
    """ takes the X-API-Key header and validate it with the X-API-Key in the database/environment"""
    if x_api_key not in full_access_key and x_api_key not in user_access_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key. Check that you are passing a 'X-API-Key' on your header."
        )
    elif x_api_key in full_access_key:
        access_type = "full"
    else:
        access_type = "user"
    return access_type