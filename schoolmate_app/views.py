import json
import shortuuid
from rest_framework import status
from django.utils import timezone
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework.response import Response
from django.http import JsonResponse as Request
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from component import send_email
from rest_framework.decorators import api_view, permission_classes
from .models import FeeCategory, School, Student, User, FeePayment, EmailOTP, BrandingSettings, Section, SchoolClass, Attendance
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.exceptions import ValidationError
from django.db import DatabaseError
import os, ast, json, uuid, random, string, razorpay, base64, requests, shortuuid, re, math
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, SchoolSerializer, StudentSerializer, FeeCategorySerializer, BrandingSettingsSerializer, SectionSerializer, SchoolClassSerializer, AttendanceSerializer, AttendanceReportSerializer

from dotenv import dotenv_values

env_vars = dotenv_values()

def generate_unique_referral_code(number):
    return shortuuid.uuid()[:number]  # Generate a short, human-readable code


# Create your views here.
def test_app_view(request):
    """
    A simple view to test the app.
    """
    return Request({'message': 'Hello, this is a test view!'})


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['POST'])
def user_registrations_views(request):
    """
    Registers a new user after validating required fields and checking school ID.
    """
    try:
        data = request.data.copy()

        required_fields = ['name', 'email', 'password', 'phone', 'tc']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({"error": f"Missing required field: {field}"}, status=400)
        email = data['email'].lower()
        # password = data['password']
        # panel_link = data["panel_link"]
        data['email'] = email
        data['role'] = data.get('role', 'parents')
        data['special_offers'] = data.get('special_offers', 0)
        data['display_name'] = data['name']

        # School ID logic based on role
        if data['role'] not in ['super-admin', "school-admin"]:
            school_id = data.get('school_id')
            if not school_id:
                return JsonResponse({"error": "Missing required field: school_id"}, status=400)

            # Validate school_id exists
            if not User.objects.filter(school_id=school_id).exists():
                return JsonResponse({"error": "Invalid school_id provided."}, status=400)

            data['school_id'] = school_id

        else:
            # Generate unique school_id for admin/school-admin
            generated_school_code = f"school_{generate_unique_referral_code(8)}"
            data['school_id'] = generated_school_code

        serializer = UserRegistrationSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        token = get_tokens_for_user(user)
        # res = send_email.send_username_and_password_function(email, email, password, panel_link)
        return Response({'token': token, 'msg': 'Registration Successful'}, status=status.HTTP_201_CREATED)

    except DRFValidationError as e:
        error_detail = e.detail
        error_messages = {
            field: messages[0] if isinstance(messages, list) else messages
            for field, messages in error_detail.items()
        }
        return JsonResponse({"error": error_messages}, status=400)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@api_view(['POST'])
def user_login_view(request):
    """
        function help us to login user

        Args:-
            email, password

        Return:-
            access_token && refresh_token && success message
    """
    try:
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:

            # Update last_login field
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            token = get_tokens_for_user(user)
            return Response({'token': token, 'msg': 'Login Successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Email or Password Is Incorrect'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as error:
        return Response({"error": str(error)}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile_view(request):
    """
        function help us to get user full details

        Args:-
            access token

        return:-
            user details dict and 200 status code
    """
    try:
        if request.method == 'GET':
            serializer = UserProfileSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': 'Profile Retrieval Failure'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout_view(request):
    """
    Function to log out a user by invalidating the refresh token.

    Args:
        refresh_token (str): The refresh token to be invalidated.

    Return:
        Success message if the token is successfully invalidated.
    """
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token is None:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken(refresh_token)
        token.blacklist()  # This method blacklists the token, invalidating it.

        return Response({'msg': 'Logout Successful'}, status=status.HTTP_200_OK)
    except TokenError as e:
        return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as error:
        return Response({"error": str(error)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    """Function to retrieve all users in the system.

    Args:
        None    
        
    Return:
        A list of all users with their details.
    """
    try:
        role = request.GET.get('role', None)
        school_id = request.GET.get('school_id', None)
        # filter user base on role
        if school_id:
            users = User.objects.filter(school_id=school_id)
        elif role:
            users = User.objects.filter(role=role)
        else:
            users = User.objects.all()
        serializer = UserProfileSerializer(users, many=True)
        return Response({"all user":serializer.data}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': 'Failed to retrieve users'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_change_password_views(request, format=None):
    """
    user can change their password by access_token

    Returns:
        message received password changed

    Args:
        successfull message
"""
    try:
        password = request.data.get("password")
        password2 = request.data.get("password2")
        user_email = request.user.email
        user = User.objects.get(email=user_email)
        if check_password(password, user.password):
            # return JsonResponse({"error": 'Please enter a password that is completely different from your last one'}, status=status.HTTP_400_BAD_REQUEST)
            return JsonResponse({"error": 'Kindly enter a new password. It must differ from your previous one.'}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
        user.set_password(password)
        user.save()
        return JsonResponse({"msg": 'Password Successfully Updated.'}, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


@api_view(['POST'])
def send_otp_views(request):
    """
    Sends a One-Time Password (OTP) to the user's email.

    Args:
        email: User's email address (required)

    Returns:
        JSON response indicating success or failure
    """
    try:
        user_email = request.data.get("email")

        if not user_email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate new OTP
        otp = generate_otp()
        expiration_time = timezone.now() + timezone.timedelta(minutes=3)

        # Create or update EmailOTP entry
        otp_instance, created = EmailOTP.objects.update_or_create(
            email=user_email,
            defaults={
                'otp': otp,
                'expiration_time': expiration_time
            }
        )

        # Send the OTP via email
        send_email_response = send_email.send_otp_on_email({}, user_email, otp)

        return Response({"message": send_email_response}, status=status.HTTP_200_OK)

    except Exception as error:
        return Response({"error": f"Failed to send OTP: {str(error)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
@api_view(['POST'])
def verify_otp_views(request):
    """
        function help us to validate otp 

        Args:
            email:- user email
            otp:- 

        return:-
            'OTP verified successfully' message and 200 status code

    """
    try:
        user_email = request.data.get("email")
        received_otp = request.data.get('otp', '')
        # print(user_email, received_otp)

        # Retrieve the latest OTP record for the user
        otp_record = EmailOTP.objects.filter(
            email=user_email).order_by('-expiration_time').first()

        if otp_record and otp_record.otp == received_otp and otp_record.expiration_time > timezone.now():
            return JsonResponse({"msg": 'OTP Successfully Verified'}, status=status.HTTP_200_OK)
        else:
            # Invalid OTP
            return JsonResponse({"error": 'OTP Invalid or Expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as error:
        # logger.error(
        #     f"getting error during verify_otp_views && error is {error}")
        return JsonResponse({"error": str(error)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def Delete_user_view(request, pk):
    """
        function help us delete the user from database

        Args:-
            email:-
            profile_id:-

        Return:-
            return message User Successfully Deleted with 200 status code
    """
    user_email = request.user.email
    try:
        profile = get_object_or_404(User, id=pk)
        profile.save()
        return Response({'message': f'User Successfully Deleted'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': f'User with email {user_email} does not exist.'}, status=status.HTTP_400_BAD_REQUEST)


# Create
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_school_view(request):
    # school_id = request.user.school_id
    # if role != 'admin':
    #     return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    data1 = request.data
    print("data1:", data1)
    # data1["school_id"] = school_id
    serializer = SchoolSerializer(data=data1)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Read All
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_schools(request):
    schools = School.objects.all()
    serializer = SchoolSerializer(schools, many=True)
    return Response(serializer.data)

# Read One
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_school(request):
    try:
        school_id = request.GET.get('school_id')
        school = School.objects.get(school_id=school_id)
    except School.DoesNotExist:
        return Response({'error': 'School not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = SchoolSerializer(school)
    return Response(serializer.data)

# Update
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_school(request, pk):
    try:
        school = School.objects.get(pk=pk)
    except School.DoesNotExist:
        return Response({'error': 'School not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = SchoolSerializer(school, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Delete
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_school(request, pk):
    try:
        school = School.objects.get(pk=pk)
    except School.DoesNotExist:
        return Response({'error': 'School not found'}, status=status.HTTP_404_NOT_FOUND)

    school.delete()
    return Response({'message': 'School deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_student(request):
    school_id = request.user.school_id
    # if role != 'admin':
    #     return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    data1 = request.data
    data1["school_id"] = school_id
    serializer = StudentSerializer(data=data1)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_students(request):
    school_id = request.user.school_id
    if not school_id:
        return Response({'error': 'school_id is required'}, status=status.HTTP_400_BAD_REQUEST)
    students = Student.objects.filter(school_id=school_id)
    serializer = StudentSerializer(students, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_students_by_class_section_views(request):
    school_id = request.user.school_id
    class_name = request.GET.get('class_name')
    section = request.GET.get('section')

    # Validate required parameters
    if not all([school_id, class_name, section]):
        return Response(
            {'error': 'school_id, class_name, and section are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Apply strict filters
    students = Student.objects.filter(
        school_id=school_id,
        student_class=class_name,
        section=section
    )

    if not students.exists():
        return Response(
            {'error': 'No students found for the given class and section'},
            status=status.HTTP_404_NOT_FOUND
        )

    serializer = StudentSerializer(students, many=True)
    return Response(serializer.data)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_student(request, student_id):
    try:
        student = Student.objects.get(id=student_id)
    except Student.DoesNotExist:
        return Response({'error': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = StudentSerializer(student)
    return Response(serializer.data)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_student(request, student_id):
    try:
        student = Student.objects.get(id=student_id)
    except Student.DoesNotExist:
        return Response({'error': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = StudentSerializer(student, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_student(request, student_id):
    try:
        student = Student.objects.get(id=student_id)
        student.delete()
        return Response({'message': 'Student deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    except Student.DoesNotExist:
        return Response({'error': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_fee_structure(request):
    school_id = request.user.school_id
    # if role != 'admin':
    #     return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    data1 = request.data
    data1["school_id"] = school_id

    serializer = FeeCategorySerializer(data=data1)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_structures_by_school(request):
    school_id = request.user.school_id
    if not school_id:
        return Response({'error': 'school_id is required'}, status=status.HTTP_400_BAD_REQUEST)

    fee_structures = FeeCategory.objects.filter(school_id=school_id)
    serializer = FeeCategorySerializer(fee_structures, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_structure_by_id(request, fee_id):
    try:
        fee = FeeCategory.objects.get(id=fee_id)
        serializer = FeeCategorySerializer(fee)
        return Response(serializer.data)
    except FeeCategory.DoesNotExist:
        return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)

# @api_view(['PUT'])
# @permission_classes([IsAuthenticated])
# def update_fee_structure(request, fee_id):
#     try:
#         fee = FeeCategory.objects.get(id=fee_id)
#     except FeeCategory.DoesNotExist:
#         return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)

#     serializer = FeeCategorySerializer(fee, data=request.data)
#     if serializer.is_valid():
#         serializer.save()
#         return Response(serializer.data)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_fee_structure(request, fee_id):
    try:
        fee = FeeCategory.objects.get(id=fee_id)
    except FeeCategory.DoesNotExist:
        return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        serializer = FeeCategorySerializer(fee, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        # return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    except ValidationError as e:
        return Response({'error': 'Invalid data', 'details': e.detail}, status=status.HTTP_400_BAD_REQUEST)

    except DatabaseError as e:
        return Response({'error': 'Database error occurred', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        return Response({'error': 'An unexpected error occurred', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_fee_structure(request, fee_id):
    try:
        fee = FeeCategory.objects.get(id=fee_id)
        fee.delete()
        return Response({'message': 'Fee Structure deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    except FeeCategory.DoesNotExist:
        return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)


# views.py
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status
# from .models import FeePayment
# from .serializers import FeePaymentSerializer
# from django.db.models import Sum

# # Create FeePayment
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.response import Response
# from rest_framework import status
# from django.db import DatabaseError
# from rest_framework.exceptions import ValidationError
from .serializers import FeePaymentSerializer

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_fee_payment(request):
    try:
        data = request.data
        school_id = request.user.school_id
        data["school_id"] = school_id
        print("Incoming Fee Payment Data:", data)

        serializer = FeePaymentSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            # 🔴 This line was missing — handle serializer validation errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except ValidationError as e:
        return Response({
            'error': 'Invalid data',
            'details': e.detail
        }, status=status.HTTP_400_BAD_REQUEST)

    except DatabaseError as e:
        return Response({
            'error': 'Database error occurred',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        return Response({
            'error': 'An unexpected error occurred',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Read all payments (or filter by student or month/year)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_payments(request):
    student_id = request.GET.get('student_id')
    month = request.GET.get('month')
    year = request.GET.get('year')
    school_id = request.user.school_id

    filters = {}
    if student_id:
        filters['student'] = student_id
    if month:
        filters['month'] = month
    if year:
        filters['year'] = year
    if school_id:
        filters['school_id'] = school_id

    payments = FeePayment.objects.filter(**filters)
    serializer = FeePaymentSerializer(payments, many=True)
    return Response(serializer.data)

# Update FeePayment
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_fee_payment(request, pk):
    try:
        fee_payment = FeePayment.objects.get(pk=pk)
    except FeePayment.DoesNotExist:
        return Response({'error': 'FeePayment not found'}, status=404)

    serializer = FeePaymentSerializer(fee_payment, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)

# Delete FeePayment
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_fee_payment(request, pk):
    try:
        fee_payment = FeePayment.objects.get(pk=pk)
        fee_payment.delete()
        return Response({'message': 'Deleted successfully'}, status=204)
    except FeePayment.DoesNotExist:
        return Response({'error': 'FeePayment not found'}, status=404)

# Get fee history for a student
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_history_by_student(request, student_id):
    payments = FeePayment.objects.filter(student_id=student_id).order_by('-year', '-month')
    serializer = FeePaymentSerializer(payments, many=True)
    return Response(serializer.data)

# Get due summary (how much student has paid vs due)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_summary_by_student(request, student_id):
    payments = FeePayment.objects.filter(student_id=student_id)
    total_due = payments.aggregate(Sum('amount_due'))['amount_due__sum'] or 0
    total_paid = payments.aggregate(Sum('amount_paid'))['amount_paid__sum'] or 0
    return Response({
        "student_id": student_id,
        "total_due": total_due,
        "total_paid": total_paid,
        "remaining": total_due - total_paid
    })



from payment_entity import razorpay_subscription
from django.conf import settings


import razorpay

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_subscription_plan_view(request):
    """
    API endpoint to create a Razorpay subscription plan and subscribe a customer for school fee payments.
    """

    try:
        data = request.data.copy()
        print("Request Data:", data)
        profileid = request.data.get("student_profileid")
        email = request.data.get("email")
        # profileid = 3
        profile = get_object_or_404(User, email=email)
        customer_id = profile.razorpay_customer_id
        
        name = request.data.get("username")
        contact = request.data.get("contact")
        client = razorpay.Client(auth=(env_vars["RAZORPAY_KEY_ID"], env_vars["RAZORPAY_KEY_SECRET"]))
        # if not customer_id:
        #     customer_id = razorpay_subscription.create_customer(client, name, email, contact)
        #     profile = get_object_or_404(User, id=profileid)
        #     profile.razorpay_customer_id = customer_id
        #     profile.save()
        # Initialize Razorpay client
        # client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        

        # Extract required fields from the payload
        period = request.data.get("period", "monthly")
        interval = int(request.data.get("interval", 1))
        name = request.data.get("name", "Test Plan 1 Month")
        # amount = int(request.data.get("amount", 500))  # in paise
        currency = request.data.get("currency", "INR")
        description = request.data.get("description", "Monthly Subscription Plan")

        # Student and subscription-specific fields
        # customer_id = request.data.get("customer_id")
        student_name = request.data.get("student_name")
        admission_year = request.data.get("admission_year")
        total_months = int(request.data.get("total_months", 12))
        monthly_fee_in_paise = int(request.data.get("monthly_fee_in_paise"))
        one_time_fee_in_paise = int(request.data.get("one_time_fee_in_paise", 0))

        # Validation: Check required fields
        # if not all([customer_id, student_name, admission_year]):
        #     return Response({"error": "Missing required fields"}, status=400)
        plan_id = profile.plain_id

        if not plan_id:
            # Prepare plan data
            plan_data = {
                "period": period,
                "interval": interval,
                "item": {
                    "name": name,
                    "amount": monthly_fee_in_paise,
                    "currency": currency,
                    "description": description
                }
            }

            # Create plan
            plan = razorpay_subscription.create_razorpay_plan_util(client, plan_data)
            # plan = {"id": "plan_123", "period": period, "interval": interval, "item": {"name": name, "amount": monthly_fee_in_paise, "currency": currency, "description": description}}
            plan_id = plan.get("id")
            profile.plain_id = plan_id
            profile.save()

        # Create subscription
        subscription = razorpay_subscription.create_school_fee_subscription(
            client,
            plan_id,
            customer_id,
            student_name,
            admission_year,
            total_months,
            monthly_fee_in_paise,
            one_time_fee_in_paise
        )
        # subscription = {
        #     "id": "sub_123",
        #     "status": "active",
        #     "customer_id": customer_id,
        #     "plan_id": plan_id,}
        profile.subscription_id = subscription['id']
        profile.save()

        if not subscription:
            return Response({"error": "Failed to create subscription"}, status=400)

        return Response({"subscription_id": subscription['id'], "status": subscription['status'], "subscription": subscription}, status=201)

    except Exception as e:
        return Response({"error": "Plan creation failed", "details": str(e)}, status=500)
    

def get_subscription_and_plan_view(request):
    """
    API endpoint to retrieve a subscription plan by its ID.
    """
    try:
        plan_id = request.GET.get("plan_id")
        subscription_id = request.GET.get("subscription_id")
        if not plan_id and subscription_id:
            return Response({"error": "plan_id and subscription_id is required"}, status=400)
        client = razorpay.Client(auth=(env_vars["RAZORPAY_KEY_ID"], env_vars["RAZORPAY_KEY_SECRET"]))
        plan = razorpay_subscription.get_razorpay_plan(client, plan_id)
        subscription_details = client.subscription.fetch(subscription_id)

        if not plan:
            return Response({"error": "Plan not found"}, status=404)    
        return Response(plan, status=200)
    except Exception as e:
        return Response({"error": "Failed to retrieve plan", "details": str(e)}, status=500)

from .models import ContentBlock
from .serializers import ContentBlockSerializer

@api_view(['POST'])
# @permission_classes([IsAuthenticated])
def create_content_block(request):
    serializer = ContentBlockSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
# @permission_classes([IsAuthenticated])
def get_content_block_by_school_id(request, school_id):
    try:
        block = ContentBlock.objects.get(school_id=school_id)
        serializer = ContentBlockSerializer(block)
        return Response(serializer.data)
    except ContentBlock.DoesNotExist:
        return Response({'error': 'Content not found'}, status=status.HTTP_404_NOT_FOUND)
    
@api_view(['GET'])
def get_content_block_by_domain(request, domain):
    try:
        # domain = request.GET.get('domain')
        block = ContentBlock.objects.get(domain=domain)
        serializer = ContentBlockSerializer(block)
        return Response(serializer.data)
    except ContentBlock.DoesNotExist:
        return Response({'error': 'Content not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PATCH'])
# @permission_classes([IsAuthenticated])
def update_content_section(request, school_id):
    """
    PATCH /api/cms/<school_id>/update/
    {
        "section": "hero",
        "data": {
            "title": "New Title"
        }
    }
    """
    try:
        block = ContentBlock.objects.get(school_id=school_id)
    except ContentBlock.DoesNotExist:
        return Response({'error': 'Content not found'}, status=status.HTTP_404_NOT_FOUND)

    section = request.data.get("section")
    new_data = request.data.get("data")

    if not section or not new_data:
        return Response({"error": "Both 'section' and 'data' fields are required."}, status=400)

    # Initialize section if not present
    if section not in block.data or not isinstance(block.data.get(section), dict):
        block.data[section] = {}

    # Update specific fields inside the section
    block.data[section].update(new_data)
    block.save()

    return Response({
        "msg": f"Section '{section}' updated successfully.",
        "data": block.data[section]
    }, status=200)


import base64
import uuid
from django.core.files.base import ContentFile
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_branding_settings(request):
    """
    POST /api/branding/
    {
        "school_id": "school_Zkjszavj",
        "color_scheme": { ... },
        "logos": { ... },
        "fonts": { ... },
        "theme_name": "Blue Ocean",
        "custom_css": "/* Custom styles */"
    }
    """
    if BrandingSettings.objects.filter(school_id=request.data.get('school_id')).exists():
        return Response({'error': 'Branding already exists for this school_id'}, status=400)

    serializer = BrandingSettingsSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_branding_settings(request, school_id):
    try:
        branding = BrandingSettings.objects.get(school_id=school_id)
        serializer = BrandingSettingsSerializer(branding)
        return Response(serializer.data)
    except BrandingSettings.DoesNotExist:
        return Response({'error': 'Branding settings not found'}, status=404)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_branding_settings(request, school_id):
    try:
        branding, _ = BrandingSettings.objects.get_or_create(school_id=school_id)
        for field in ['color_scheme', 'logos', 'fonts', 'theme_name', 'custom_css']:
            if field in request.data:
                setattr(branding, field, request.data[field])
        branding.save()
        serializer = BrandingSettingsSerializer(branding)
        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_logo(request, school_id):
    logo_type = request.data.get('logo_type')
    file_data = request.data.get('file')

    if not logo_type or not file_data:
        return Response({'error': 'logo_type and file are required'}, status=400)

    try:
        branding, _ = BrandingSettings.objects.get_or_create(school_id=school_id)

        # Decode base64 file
        format, imgstr = file_data.split(';base64,')
        ext = format.split('/')[-1]
        file_name = f"{logo_type}_{uuid.uuid4()}.{ext}"
        file = ContentFile(base64.b64decode(imgstr), name=file_name)

        # Upload the file to storage (you can use your own method)
        from django.core.files.storage import default_storage
        path = default_storage.save(f"branding/{school_id}/{file_name}", file)
        full_url = default_storage.url(path)

        branding.logos[{
            "main": "main_logo_url",
            "favicon": "favicon_url",
            "footer": "footer_logo_url"
        }[logo_type]] = full_url
        branding.save()

        return Response({
            "message": f"{logo_type} logo uploaded successfully",
            "url": full_url
        })
    except Exception as e:
        return Response({'error': str(e)}, status=400)


# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status
from .models import SchoolGeneralSettings
from .serializers import SchoolGeneralSettingsSerializer

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_school_settings(request):
    """
    POST /api/school/settings/
    {
        "school_id": "school_Zkjszavj",
        "contact_info": { ... },
        "social_links": { ... },
        "footer_content": { ... },
        "basic_info": { ... },
        "seo_metadata": { ... }
    }
    """
    if SchoolGeneralSettings.objects.filter(school_id=request.data.get('school_id')).exists():
        return Response({'error': 'Settings already exist for this school_id'}, status=400)

    serializer = SchoolGeneralSettingsSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_school_settings(request, school_id):
    try:
        settings = SchoolGeneralSettings.objects.get(school_id=school_id)
        return Response(SchoolGeneralSettingsSerializer(settings).data)
    except SchoolGeneralSettings.DoesNotExist:
        return Response({'error': 'Settings not found'}, status=404)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_school_settings(request, school_id):
    settings, _ = SchoolGeneralSettings.objects.get_or_create(school_id=school_id)
    # Loop through sections: contact_info, social_links, footer_content, basic_info, seo_metadata
    for key in ['contact_info', 'social_links', 'footer_content', 'basic_info', 'seo_metadata']:
        if key in request.data:
            current_data = getattr(settings, key, {})
            current_data.update(request.data[key])
            setattr(settings, key, current_data)
    settings.save()
    return Response(SchoolGeneralSettingsSerializer(settings).data)



# class management start
# 🔹 List All or Create New Class
@api_view(['GET', 'POST'])
def school_class_list_create(request):
    if request.method == 'GET':
        # Try to get from query param, fallback to user's school_id
        school_id = request.GET.get('school_id')

        if school_id:
            classes = SchoolClass.objects.filter(school_id=school_id)
        else:
            classes = SchoolClass.objects.all()
        serializer = SchoolClassSerializer(classes, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = SchoolClassSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# 🔹 Retrieve, Update or Delete Class by ID
@api_view(['GET', 'PUT', 'DELETE'])
def school_class_detail(request, pk):
    try:
        school_class = SchoolClass.objects.get(pk=pk)
    except SchoolClass.DoesNotExist:
        return Response({"error": "Class not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = SchoolClassSerializer(school_class)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = SchoolClassSerializer(school_class, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        school_class.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
# class management end

# section managment start
@api_view(['GET', 'POST'])
def section_list_create(request):
    if request.method == 'GET':
        school_id = request.GET.get('school_id')
        class_id = request.GET.get('class_id')  # This is the class_ref foreign key

        filters = {}

        if school_id:
            filters['school_id'] = school_id

        if class_id:
            filters['class_ref_id'] = class_id

        sections = Section.objects.filter(**filters)
        serializer = SectionSerializer(sections, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = SectionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 🔹 Retrieve, update, delete section by ID
@api_view(['DELETE'])
def section_detail(request, pk):
    try:
        section = Section.objects.get(pk=pk)
    except Section.DoesNotExist:
        return Response({"error": "Section not found"}, status=status.HTTP_404_NOT_FOUND)
    if request.method == 'DELETE':
        section.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



# section managment end
# attendence management start
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_attendance_view(request):
    user = request.user
    records = request.data.get('records', [])
    
    if not records:
        return Response({'error': 'No attendance records provided.'}, status=status.HTTP_400_BAD_REQUEST)

    responses = []

    for record in records:
        student_id = record.get('student_id')
        school_id = record.get('school_id', user.school_id)  # Use user's school_id if not provided
        class_id = record.get('class_id')
        section_id = record.get('section_id')
        date = record.get('date')
        status_value = record.get('status')

        if not all([student_id, class_id, section_id, date, status_value]):
            responses.append({'student_id': student_id, 'error': 'Missing required fields.'})
            continue

        try:
            attendance_obj, created = Attendance.objects.update_or_create(
                student_id=student_id,
                date=date,
                defaults={
                    'class_id_id': class_id,
                    'section_id_id': section_id,
                    'status': status_value,
                    'marked_by': user,
                    'school_id' : school_id  # Ensure school_id is set
                }
            )
            responses.append({
                'student_id': student_id,
                'status': 'created' if created else 'updated'
            })
        except Exception as e:
            responses.append({'student_id': student_id, 'error': str(e)})

    return Response({'results': responses}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_attendance_view(request):
    class_id = request.GET.get('class_id')
    section_id = request.GET.get('section_id')
    date = request.GET.get('date')

    if not all([class_id, section_id, date]):
        return Response({'error': 'class_id, section_id, and date are required.'}, status=status.HTTP_400_BAD_REQUEST)

    attendance = Attendance.objects.filter(class_id_id=class_id, section_id_id=section_id, date=date)
    serializer = AttendanceSerializer(attendance, many=True)
    return Response(serializer.data)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_attendance_view(request, student_id, date):
    try:
        attendance = Attendance.objects.get(student_id=student_id, date=date)
        attendance.delete()
        return Response({'message': 'Attendance deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
    except Attendance.DoesNotExist:
        return Response({'error': 'Attendance record not found.'}, status=status.HTTP_404_NOT_FOUND)


from datetime import datetime
# from .models import Attendance
# from .serializers import AttendanceSerializer

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def attendance_report_view(request):
    class_id = request.GET.get('class_id')
    section_id = request.GET.get('section_id')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # Validate input
    if not all([class_id, section_id, start_date, end_date]):
        return Response(
            {'error': 'class_id, section_id, start_date, and end_date are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").date()
        end = datetime.strptime(end_date, "%Y-%m-%d").date()

        attendance_qs = Attendance.objects.filter(
            class_id_id=class_id,
            section_id_id=section_id,
            date__range=(start, end)
        ).order_by('date')

        # serializer = AttendanceSerializer(attendance_qs, many=True)
        serializer = AttendanceReportSerializer(attendance_qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except ValueError:
        return Response({'error': 'Invalid date format. Use YYYY-MM-DD'}, status=status.HTTP_400_BAD_REQUEST)

from datetime import datetime, date


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def total_attendance_summary_range_view(request):
    user = request.user
    school_id = user.school_id

    class_id = request.GET.get('class_id')
    section_id = request.GET.get('section_id')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # Default to today's date if not provided
    today = date.today()
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").date() if start_date else today
        end = datetime.strptime(end_date, "%Y-%m-%d").date() if end_date else today
    except ValueError:
        return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)

    if start > end:
        return Response({'error': 'start_date cannot be after end_date.'}, status=status.HTTP_400_BAD_REQUEST)

    # Step 1: Filter students
    student_filter = {'school_id': school_id}
    if class_id:
        student_filter['student_class'] = class_id
    if section_id:
        student_filter['section'] = section_id

    students = Student.objects.filter(**student_filter)
    total_students = students.count()

    # Step 2: Attendance filtering
    attendance_qs = Attendance.objects.filter(
        school_id=school_id,
        student__in=students,
        date__range=(start, end)
    )

    present = attendance_qs.filter(status='present').count()
    absent = attendance_qs.filter(status='absent').count()
    late = attendance_qs.filter(status='late').count()

    # Attendance rate = present / (total_students * total_days) * 100
    total_days = (end - start).days + 1
    expected_marked = total_students * total_days

    attendance_rate = round((present / expected_marked) * 100, 2) if expected_marked > 0 else 0

    return Response({
        "start_date": start.strftime("%Y-%m-%d"),
        "end_date": end.strftime("%Y-%m-%d"),
        "total_students": total_students,
        "total_days": total_days,
        "present": present,
        "absent": absent,
        "late": late,
        "attendance_rate": f"{attendance_rate}%"
    })
