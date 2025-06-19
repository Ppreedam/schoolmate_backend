import uuid
from django.db import models
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
#  Custom User Manager
class UserManager(BaseUserManager):
  def create_user(self, email, name, phone, is_active, tc, role, special_offers, school_id, password=None, password2=None):
      """
      Creates and saves a User with the given email, name, tc and password.
      """
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email = self.normalize_email(email),
          display_name = name,
          phone = phone,
          school_id = school_id,
          is_active = is_active,
          role = role,
          special_offers = special_offers,
          tc = tc,
      )

      user.set_password(password)
      user.save(using=self._db)
      return user

  def create_superuser(self, email, name, tc, password=None):
      """
      Creates and saves a superuser with the given email, name, tc and password.
      """
      user = self.create_user(
          email,
          password=password,
          name=name,
          tc=tc,
      )
      user.is_admin = True
      user.save(using=self._db)
      return user

#  Custom User Model
class User(AbstractBaseUser):
  email = models.EmailField(verbose_name='Email', max_length=255, unique=True,)
  display_name = models.CharField(max_length=200)
  phone = models.CharField(max_length=200, default='', blank=True)
  school_id = models.CharField(max_length=50, default='', blank=True)
  role = models.CharField(max_length=100, default='')
  special_offers = models.DecimalField(max_digits=10, decimal_places=2, default=0)
  tc = models.BooleanField()
  is_active = models.BooleanField(default=False)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['name', 'tc']

  def __str__(self):
      return self.email

  def has_perm(self, perm, obj=None):
      "Does the user have a specific permission?"
      # Simplest possible answer: Yes, always
      return self.is_admin

  def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

  @property
  def is_staff(self):
      "Is the user a member of staff?"
      # Simplest possible answer: All admins are staff
      return self.is_admin
  
from django.contrib.postgres.fields import ArrayField, JSONField  # Use JSONField depending on Django version

class School(models.Model):
    school_name = models.CharField(max_length=255)
    # school_code = models.CharField(max_length=100, unique=True)
    school_id = models.CharField(max_length=50, unique=True)  # Unique identifier for the school
    theme_color = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    domain = models.CharField(max_length=255)
    contact_email = models.EmailField(unique=True)
    contact_phone = models.CharField(max_length=20)
    address = models.TextField()
    logo_url = models.URLField()
    is_active = models.BooleanField(default=True)

    # Features as a JSONField
    features = models.JSONField(default=dict)  # Use `from django.db.models import JSONField` if Django < 3.1

    # School website details as a JSONField
    school_website_details_dict = models.JSONField(default=dict)

    def __str__(self):
        return self.school_code

class Student(models.Model):
    student_name = models.CharField(max_length=255)
    parent_name = models.CharField(max_length=255)
    relationship = models.CharField(max_length=50)
    admission_number = models.CharField(max_length=100, unique=True)
    student_class = models.CharField(max_length=100)
    section = models.CharField(max_length=10)
    date_of_birth = models.DateField()
    roll_number = models.CharField(max_length=50)
    gender = models.CharField(max_length=10)
    mobile_number = models.CharField(max_length=15)
    email = models.EmailField(blank=True, null=True)
    school_id = models.CharField(max_length=50)
    
    address = models.JSONField(default=dict)  # city, state, country, postal_code, admission_date
    regular_fees = models.JSONField(default=dict)  # tuition_fee, monthly_fee, etc.

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.student_name
    

class FeeStructure(models.Model):
    name = models.CharField(max_length=255)
    amount = models.FloatField()
    due_date = models.DateField()
    payment_status = models.BooleanField(default=False)
    frequency = models.CharField(max_length=50)  # e.g., Regular, Quarterly, One-Time
    student_class = models.CharField(max_length=100)
    section = models.CharField(max_length=10)
    # school = models.ForeignKey('School', on_delete=models.CASCADE, related_name='fee_structures')
    school_id = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.student_class} {self.section}"


class FeePayment(models.Model):
    school_id = models.CharField(max_length=50)  # Consider ForeignKey if you have a School model
    student = models.ForeignKey('Student', on_delete=models.CASCADE, related_name='fee_payments')
    month = models.CharField(max_length=15)  # e.g., "June"
    year = models.IntegerField(default=timezone.now().year)
    amount_due = models.DecimalField(max_digits=10, decimal_places=2)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    is_paid = models.BooleanField(default=False)
    due_date = models.DateField(null=True, blank=True)
    payment_date = models.DateField(null=True, blank=True)
    transaction_id = models.CharField(max_length=100, null=True, blank=True)
    fee_type = models.CharField(max_length=50,
        choices=[
            ('regular', 'Regular'),
            ('books', 'Books'), 
            ('uniform', 'Uniform'),
            ('bag', 'Bag'),
            ('transport', 'Transport'),
            ('other', 'Other')
        ],
        default='regular'
    )
    mode = models.CharField(max_length=50,
        choices=[
            ('cash', 'Cash'),
            ('upi', 'UPI'),
            ('netbanking', 'Net Banking'),
            ('card', 'Card'),
            ('cheque', 'Cheque'),
            ('wallet', 'Wallet')
        ],
        null=True, blank=True
    )
    remarks = models.TextField(null=True, blank=True)  # optional: for any custom note like "paid partially"
    invoice_id = models.CharField(max_length=100, null=True, blank=True, unique=True)

    class Meta:
        ordering = ['-year', 'month']
        unique_together = ('student', 'month', 'year', 'fee_type')

    def __str__(self):
        return f"{self.student.student_name} - {self.fee_type} - {self.month} {self.year}"

