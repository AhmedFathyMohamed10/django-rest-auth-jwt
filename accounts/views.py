from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework import generics

from .serializers import RegisterSerializer, UserSerializer

from django.contrib.auth import authenticate
from django.contrib.auth.models import User

# Create your views here.

# Register a new user

@api_view(['POST'])
def register(request):
    data = request.data
    serializer = RegisterSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        data = {
            'user': serializer.data
        }
    else:
        data = serializer.errors
    return Response(data, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login_user(request):
    data = request.data
    username = data['username']
    password = data['password']
    user = authenticate(username=username, password=password)
    if user is not None:
        token, created = Token.objects.get_or_create(user=user)

        data = {
            'user': user.username,
            'token': token.key
        }
        return Response(data, status=status.HTTP_200_OK)
    else: 
        data = {'error': 'Invalid credentials'}
        return Response(data, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view( ['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    # Handle if the user is already logged out
    try:
        request.user.auth_token.delete()
        data = {'Success': 'You are logged out'}
        return Response(data, status=status.HTTP_200_OK)
    except request.user.auth_token.DoesNotExist:
        data = {'Error': 'You are already logged out'}
        return Response(data, status=status.HTTP_400_BAD_REQUEST)

   
class ListUsers(generics.ListAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()

    permission_classes = [
        IsAuthenticated
    ]


class GetUser(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    permission_classes = [
        IsAuthenticated
    ]