from django.shortcuts import render
from rest_framework import viewsets, generics, status
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
import requests
from blood_donation import settings
from .models import *
from django.utils.crypto import get_random_string

from .serializers import *


# Create your views here.
class SignUpView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            if User.objects.filter(email=request.data['email']).exists():
                return Response({'message': 'Email is already Exist'}, status=status.HTTP_409_CONFLICT)

            if 'password' in request.data:
                request.data['password'] = make_password(request.data['password'])
                # university = UniversityName.objects.get(pk=request.data['university_name'], is_deleted=False)
                # request.data['university_name'] = university

            response = self.create(request, *args, **kwargs)
            ctx = response.data
            del response.data["password"]
            response.data['gender'] = User.TYPE_CHOICES[int(response.data['gender']) - 1][1]
            response.data['role'] = User.ROLE[int(response.data['role']) - 1][1]
            # response.data['registration_date'] = response.data["created_at"]

            # email_context = {'email': request.data['email'], 'first_name': response.data['first_name'],
            #                  'last_name': response.data['last_name']}
            # hook_set.registration_email(email_context)
            # emailverify_context = {'email': response.data['email'], 'secret_hash': response.data['secret_hash'] , 'domain':request.get_host()}
            # hook_set.referral_invitation_email(emailverify_context)
            return Response(ctx, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SignInView(generics.CreateAPIView):

    def post(self, request, *args, **kwargs):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                user = authenticate(request, username=request.data['email'], password=request.data['password'])
                if user is not None:
                    if user.banned:
                        return Response({"message": "Your account is suspended."}, status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        login(request, user)
                        ctx = []
                        ctx = {'id': user.pk,
                               'first_name': user.first_name,
                               'last_name': user.last_name,
                               'email': user.email,
                               'phone_number': user.phone_number,
                               'dob': user.dob,
                               # 'gender': User.TYPE_CHOICES[int(user.gender) - 1][1],
                               'university_name': user.university_name,
                               'seat_no': user.seat_no,
                               }

                        return Response(ctx, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Invalid Email or Password"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.filter(is_deleted=False)
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        try:
            query_set = User.objects.filter(pk=pk, is_deleted=False)
            if query_set.exists():

                user_detail = query_set.values('id', 'first_name', 'last_name', 'email', 'phone_number', 'image_url',
                                               'dob', 'gender', 'city', 'address', 'university_name', 'seat_no',
                                               'blood_group', 'no_of_donations')
                university_name = UniversityName.objects.get(pk=user_detail[0]["university_name"], is_deleted=False)

                ctx = {'id': user_detail[0]["id"],
                       'first_name': user_detail[0]["first_name"],
                       'last_name': user_detail[0]["last_name"],
                       'email': user_detail[0]["email"],
                       'phone_number': user_detail[0]["phone_number"],
                       'image_url': user_detail[0]["image_url"],
                       'dob': user_detail[0]["dob"],
                       'gender': User.TYPE_CHOICES[int(user_detail[0]["gender"]) - 1][1],
                       'city': user_detail[0]["city"],
                       'address': user_detail[0]["address"],
                       'university_name': university_name.name,
                       'seat_no': user_detail[0]["seat_no"],
                       'blood_group': user_detail[0]["blood_group"],
                       'no_of_donations': user_detail[0]["no_of_donations"]}

                return Response(ctx, status=status.HTTP_200_OK)
            else:

                return Response({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, *args, **kwargs):
        try:
            user_detail = User.objects.filter(pk=pk, is_deleted=False)
            if user_detail.exists():
                response = self.partial_update(request, *args, **kwargs)
                response.data["gender"] = User.TYPE_CHOICES[int(response.data["gender"]) - 1][1]
                del response.data["password"]
                return response
            else:
                return Response({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UniversityNameView(generics.ListCreateAPIView):
    queryset = UniversityName.objects.filter(is_deleted=False)
    serializer_class = UniversityNameSerializer
    permission_classes = [IsAuthenticated]


class UniversityNameRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UniversityName.objects.filter(is_deleted=False)
    serializer_class = UniversityNameSerializer
    permission_classes = [IsAuthenticated]


class CategoryView(generics.ListCreateAPIView):
    queryset = Category.objects.filter(is_deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]


class CategoryRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Category.objects.filter(is_deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]


class PostView(generics.ListCreateAPIView):
    queryset = Post.objects.filter(is_deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]


class PostRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.filter(is_deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]


class EventView(generics.ListCreateAPIView):
    queryset = Event.objects.filter(is_deleted=False)
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]


class EventRUDView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Event.objects.filter(is_deleted=False)
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]


# // T o k e n i z a t i on // #

@permission_classes([AllowAny])
class Token(generics.CreateAPIView):
    ''' Gets tokens with username and password. Input should be in the format:{"username": "username", "password":
    "1234abcd"} '''

    def post(self, request, *args, **kwargs):
        r = requests.post(
            settings.base_url_auth + '/o/token/',
            data={
                'grant_type': 'password',
                'username': request.data['email'],
                'password': request.data['password'],
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET,
            },
        )
        return Response(r.json())


@permission_classes([AllowAny])
class RefreshToken(generics.CreateAPIView):
    '''
    Registers user to the server. Input should be in the format:
    {"refresh_token": "<token>"}
    '''

    def post(self, request, *args, **kwargs):
        r = requests.post(
            settings.base_url_auth + '/o/token/',
            data={
                'grant_type': 'refresh_token',
                'refresh_token': request.data['refresh_token'],
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET,
            },
        )
        return Response(r.json())


@permission_classes([AllowAny])
class RevokeToken(generics.CreateAPIView):
    '''
    Method to revoke tokens.
    {"token": "<token>"}
    '''

    def post(self, request, *args, **kwargs):
        r = requests.post(
            settings.base_url_auth + '/o/revoke_token/',
            data={
                'token': request.data['token'],
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET,
            },
        )
        # If it goes well return sucess message (would be empty otherwise)
        if r.status_code == requests.codes.ok:
            return Response({'message': 'token revoked'}, r.status_code)
        # Return the error if it goes badly
        return Response(r.json(), r.status_code)
