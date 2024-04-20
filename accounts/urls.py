from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register),
    path('login/', views.login_user),
    path('logout/', views.logout_user),
    path('change-password/', views.change_password),

    path('users/', views.ListUsers.as_view()),
    path('users/<int:pk>/', views.GetUser.as_view())

]
