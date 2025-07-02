from django.contrib.auth.models import User

from rest_framework import serializers
from .models import BrandingSettings
from .models import BrandingSettings
from .models import BrandingSettings, SchoolClass
from schoolmate_app.models import User, School, Student, FeePayment, FeeCategory, ContentBlock, BrandingSettings, SchoolGeneralSettings


# class UserRegistrationSerializer(serializers.ModelSerializer):
#   class Meta:
#     model = User
#     fields=['email', 'display_name', 'password', 'phone', 'tc', 'is_active', 'role', 'special_offers','school_id']
#     extra_kwargs={
#       'password':{'write_only':True}
#     }

#   def create(self, validate_data):
#     return User.objects.create_user(**validate_data)
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'email', 'display_name', 'password', 'phone',
            'tc', 'is_active', 'role', 'special_offers', 'school_id'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'is_active': {'read_only': True},  # Optional: prevent manual override from frontend
        }

    def create(self, validated_data):
        # Extract and map necessary fields
        name = validated_data.pop('display_name')
        email = validated_data['email']
        phone = validated_data['phone']
        tc = validated_data['tc']
        role = validated_data.get('role', 'parents')
        special_offers = validated_data.get('special_offers', 0)
        school_id = validated_data['school_id']
        password = validated_data['password']
        is_active = validated_data.get('is_active', True)  # default to True unless you want otherwise

        return User.objects.create_user(
            email=email,
            name=name,
            phone=phone,
            tc=tc,
            role=role,
            special_offers=special_offers,
            school_id=school_id,
            password=password,
            is_active=is_active,
        )


class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'display_name', 'last_login', 'role']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = ['id', 'email', 'display_name', 'phone', 'role', 'special_offers', 'school_id']
        fields = '__all__'

class SchoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = School
        fields = '__all__'



class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = '__all__'

class FeeCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = FeeCategory
        fields = '__all__'


class FeePaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeePayment
        fields = '__all__'

class ContentBlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContentBlock
        fields = '__all__'


class BrandingSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BrandingSettings
        fields = '__all__'

class SchoolGeneralSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolGeneralSettings
        fields = '__all__'

class SchoolClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolClass
        fields = '__all__'

from rest_framework import serializers
from .models import SchoolClass, Section

class SectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Section
        fields = '__all__'
