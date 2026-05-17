"""
Create Test Users with Different Roles
Run: python create_test_users.py
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from apps.accounts.models import User

def create_test_users():
    """Create 3 test users with different roles"""
    
    users = [
        {
            'username': 'admin',
            'email': 'admin@securewatch.com',
            'password': 'admin123',
            'role': 'admin',
            'first_name': 'Admin',
            'last_name': 'User'
        },
        {
            'username': 'analyst',
            'email': 'analyst@securewatch.com',
            'password': 'analyst123',
            'role': 'analyst',
            'first_name': 'Security',
            'last_name': 'Analyst'
        },
        {
            'username': 'viewer',
            'email': 'viewer@securewatch.com',
            'password': 'viewer123',
            'role': 'viewer',
            'first_name': 'View',
            'last_name': 'Only'
        }
    ]
    
    print("Creating test users...\n")
    
    for user_data in users:
        # Check if user exists
        try:
            user = User.objects.get(username=user_data['username'])
            print(f"User '{user_data['username']}' already exists. Updating password...")
            user.set_password(user_data['password'])
            user.role = user_data['role']
            user.save()
        except User.DoesNotExist:
            # Create user
            user = User.objects.create_user(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password'],
                role=user_data['role'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name']
            )
            print(f"Created: {user_data['username']} ({user_data['role']})")
        
        print(f"   Email: {user_data['email']}")
        print(f"   Password: {user_data['password']}\n")
    
    print("=" * 60)
    print("Test users created successfully!")
    print("=" * 60)
    print("\nLOGIN CREDENTIALS:\n")
    print("1. ADMIN (Full Access)")
    print("   Username: admin")
    print("   Password: admin123\n")
    print("2. ANALYST (View & Analyze)")
    print("   Username: analyst")
    print("   Password: analyst123\n")
    print("3. VIEWER (Read Only)")
    print("   Username: viewer")
    print("   Password: viewer123\n")
    print("Login at: http://localhost:8000/login/")
    print("=" * 60)

if __name__ == "__main__":
    create_test_users()
