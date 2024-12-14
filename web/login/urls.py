from django.urls import  path
from django.contrib.auth import views as auth_views


from . import views as login_views

urlpatterns = [
    path(
        '',
        auth_views.LoginView.as_view(template_name='login.html'),
        name='login'),
    
]
