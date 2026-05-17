from django.contrib.auth import get_user_model
from social_core.pipeline.user import create_user
from social_core.exceptions import AuthForbidden

User = get_user_model()

def create_or_update_user(backend, user, response, details, *args, **kwargs):
    """Custom pipeline step - create/update user from Google OAuth"""
    if user:
        # User exists, update details
        user.email = details.get('email', user.email)
        user.username = details.get('username', user.username) or user.email.split('@')[0]
        user.first_name = details.get('first_name', '')
        user.last_name = details.get('last_name', '')
        user.save()
        return {'is_new': False}
    
    # Create new user
    email = details.get('email')
    if not email:
        raise AuthForbidden('No email from Google')
    
    username = details.get('username') or email.split('@')[0]
    password = User.objects.make_random_password()
    
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=details.get('first_name', ''),
        last_name=details.get('last_name', ''),
        role='viewer'  # Default role
    )
    
    return {'is_new': True, 'user': user}

