import json
import shortuuid
from rest_framework import status
from django.utils import timezone
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework.response import Response
from django.http import JsonResponse as Request
from django.shortcuts import get_object_or_404
from .models import FeeStructure, School, Student, User, FeePayment
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError as DRFValidationError
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, SchoolSerializer, StudentSerializer, FeeStructureSerializer

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

        data['email'] = data['email'].lower()
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
        # filter user base on role
        if role:
            users = User.objects.filter(role=role)
        else:
            users = User.objects.all()
        serializer = UserProfileSerializer(users, many=True)
        return Response({"all user":serializer.data}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': 'Failed to retrieve users'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Create
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_school_view(request):
    # school_id = request.user.school_id
    # if role != 'admin':
    #     return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    data1 = request.data
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
def get_school(request, pk):
    try:
        school = School.objects.get(pk=pk)
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

    serializer = FeeStructureSerializer(data=data1)
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

    fee_structures = FeeStructure.objects.filter(school_id=school_id)
    serializer = FeeStructureSerializer(fee_structures, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_structure_by_id(request, fee_id):
    try:
        fee = FeeStructure.objects.get(id=fee_id)
        serializer = FeeStructureSerializer(fee)
        return Response(serializer.data)
    except FeeStructure.DoesNotExist:
        return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_fee_structure(request, fee_id):
    try:
        fee = FeeStructure.objects.get(id=fee_id)
    except FeeStructure.DoesNotExist:
        return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = FeeStructureSerializer(fee, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_fee_structure(request, fee_id):
    try:
        fee = FeeStructure.objects.get(id=fee_id)
        fee.delete()
        return Response({'message': 'Fee Structure deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    except FeeStructure.DoesNotExist:
        return Response({'error': 'Fee Structure not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_fee_payment(request):
    data = request.data
    payment = FeePayment.objects.create(data=data)
        # school_id=data['school_id'],
        # student_id=data['student_id'],
        # month=data['month'],
        # year=data['year'],
        # amount_due=data['amount_due'],
        # amount_paid=data['amount_paid'],
        # is_paid=data['is_paid'],
        # payment_date=data.get('payment_date'),
        # transaction_id=data.get('transaction_id'),
        # mode=data.get('mode')
    
    return JsonResponse({"message": "Payment record created", "id": payment.id}, status=201)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fee_payment(request, payment_id):
    payment = get_object_or_404(FeePayment, id=payment_id)
    return JsonResponse({
        "school_id": payment.school_id,
        "student_id": payment.student.id,
        "month": payment.month,
        "year": payment.year,
        "amount_due": float(payment.amount_due),
        "amount_paid": float(payment.amount_paid),
        "is_paid": payment.is_paid,
        "payment_date": payment.payment_date,
        "transaction_id": payment.transaction_id,
        "mode": payment.mode,
    })


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_fee_payment(request, payment_id):
    payment = get_object_or_404(FeePayment, id=payment_id)
    data = json.loads(request.body)

    payment.amount_due = data.get('amount_due', payment.amount_due)
    payment.amount_paid = data.get('amount_paid', payment.amount_paid)
    payment.is_paid = data.get('is_paid', payment.is_paid)
    payment.payment_date = data.get('payment_date', payment.payment_date)
    payment.transaction_id = data.get('transaction_id', payment.transaction_id)
    payment.mode = data.get('mode', payment.mode)
    payment.save()

    return JsonResponse({"message": "Payment updated"})

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_fee_payment(request, payment_id):
    payment = get_object_or_404(FeePayment, id=payment_id)
    payment.delete()
    return JsonResponse({"message": "Payment deleted"})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_student_payment_history_by_school(request, school_id, student_id):
    payments = FeePayment.objects.filter(school_id=school_id, student_id=student_id).order_by('year', 'month')
    data = [{
        "month": p.month,
        "year": p.year,
        "amount_due": float(p.amount_due),
        "amount_paid": float(p.amount_paid),
        "is_paid": p.is_paid,
        "payment_date": p.payment_date,
        "mode": p.mode,
        "transaction_id": p.transaction_id,
    } for p in payments]
    return JsonResponse(data, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_payments_by_school(request, school_id):
    payments = FeePayment.objects.filter(school_id=school_id).order_by('student', 'year', 'month')
    data = [{
        "student_id": p.student.id,
        "student_name": p.student.name,
        "month": p.month,
        "year": p.year,
        "amount_due": float(p.amount_due),
        "amount_paid": float(p.amount_paid),
        "is_paid": p.is_paid,
        "payment_date": p.payment_date,
        "mode": p.mode,
        "transaction_id": p.transaction_id,
    } for p in payments]
    return JsonResponse(data, safe=False)

