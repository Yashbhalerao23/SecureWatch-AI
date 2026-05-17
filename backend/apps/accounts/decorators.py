"""
Role-Based Access Control Decorators
"""
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.http import JsonResponse


def role_required(*roles):
    """
    Decorator to restrict access based on user roles
    Usage: @role_required('admin', 'analyst')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            
            if request.user.role not in roles and not request.user.is_superuser:
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard')
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def admin_required(view_func):
    """Decorator to restrict access to admins only"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if not request.user.is_admin:
            messages.error(request, 'Admin access required.')
            return redirect('dashboard')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def analyst_required(view_func):
    """Decorator to restrict access to analysts and admins"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if not request.user.is_analyst:
            messages.error(request, 'Analyst access required.')
            return redirect('dashboard')
        
        return view_func(request, *args, **kwargs)
    return wrapper


# API Decorators
def api_role_required(*roles):
    """API version of role_required decorator"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return JsonResponse({'error': 'Authentication required'}, status=401)
            
            if request.user.role not in roles and not request.user.is_superuser:
                return JsonResponse({'error': 'Permission denied'}, status=403)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
