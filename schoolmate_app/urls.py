from . import views
from schoolmate_backend.urls import path



urlpatterns = [
    # Schoolmate_UserAuth
    path("test/", views.test_app_view, name="get_app"),
    path("signup/", views.user_registrations_views, name="user_registration"),
    path("signin/", views.user_login_view, name="user_login"),
    path("profile/", views.user_profile_view, name="user_profile"),
    path("logout/", views.user_logout_view, name="user_logout"),
    path("get/all/users/", views.get_all_users, name="get_all_users"),
    path('changepassword/', views.user_change_password_views, name='changepassword'),
    path('send_otp_on_email/', views.send_otp_views, name='send_otp'),
    path('verify_otp/', views.verify_otp_views, name='verify_otp'),
    path('delete/user/<int:pk>/', views.Delete_user_view, name='delete_user'),
    # create school
    path("create/school/", views.create_school_view, name="create_school"),
    path("schools/", views.list_schools, name="list_schools"), # list all schools
    path("specific/school", views.get_school, name="get_school"), # get school by id
    path("update/school/<int:pk>/", views.update_school, name="update_school"), # update school by id
    path("delete/school/<int:pk>/", views.delete_school, name="delete_school"), # delete school by id

    # create student
    path('get/all/students/', views.get_all_students, name='get_all_students'),
    path('get/students', views.get_all_students_by_class_section_views, name='get_all_students'),
    path('students/create/', views.create_student, name='create_student'),
    path('students/<int:student_id>/', views.get_student, name='get_student'),
    path('students/<int:student_id>/update/', views.update_student, name='update_student'),
    path('students/<int:student_id>/delete/', views.delete_student, name='delete_student'),

    # Fee Structure
    path('create/fees/categories/', views.create_fee_structure, name='create_fee_structure'),
    path('get/all/fees/categories/', views.get_fee_structures_by_school, name='get_fee_structures_by_school'),
    path('fees/<int:fee_id>/categories/', views.get_fee_structure_by_id, name='get_fee_structure_by_id'),
    path('fees/<int:fee_id>/update/', views.update_fee_structure, name='update_fee_structure'),
    path('fees/<int:fee_id>/delete/', views.delete_fee_structure, name='delete_fee_structure'),

    
    # Fee Payment History
    # path('fees/payment/create/', views.create_fee_payment, name='create_fee_payment'),
    # path('fees/payment/<int:payment_id>/', views.get_fee_payment, name='get_fee_payment'),
    # path('fees/payment/<int:payment_id>/update/', views.update_fee_payment, name='update_fee_payment'),
    # path('fees/payment/<int:payment_id>/delete/', views.delete_fee_payment, name='delete_fee_payment'),

    # # Get by school/student
    # path('fees/history/<str:school_id>/<int:student_id>/', views.get_student_payment_history_by_school, name='student_fee_history_by_school'),
    # path('fees/history/<str:school_id>/', views.get_all_payments_by_school, name='all_fee_history_by_school'),
    path('create/fee/history/', views.create_fee_payment, name="fees categories"), #Add fee record
    path('fee/history/', views.get_fee_payments), #Filter fee data
    path('fee/update/<int:pk>/', views.update_fee_payment), #Update fee record
    path('fee/delete/<int:pk>/', views.delete_fee_payment), #Delete fee record
    path('fee/history/<int:student_id>/', views.get_fee_history_by_student),    # Get fee history by student ID
    path('fee/summary/<int:student_id>/', views.get_fee_summary_by_student),     # Get fee summary by student ID
    # payment gateway
    path('create/subsctription/', views.create_subscription_plan_view, name='create_subscription'),  # Create subscription
    path("plan/details/", views.get_subscription_and_plan_view, name="get_subscription_plan"),  # Get subscription plan by ID
    # website settings
    path('api/content/', views.create_content_block, name='create_content'),
    path('api/content/<str:school_id>/', views.get_content_block_by_school_id, name='get_content_by_school'),
    path('api/content/by-domain/<str:domain>/', views.get_content_block_by_domain, name='get_content_by_domain'),
    path('api/content/<str:school_id>/update/', views.update_content_section, name='update_section'),

    path('api/branding/', views.create_branding_settings, name='create_branding'),  # <-- New
    path('api/branding/<str:school_id>/', views.get_branding_settings, name='get_branding'),
    path('api/branding/<str:school_id>/update/', views.update_branding_settings, name='update_branding'),
    path('api/branding/<str:school_id>/upload-logo', views.upload_logo, name='upload_logo'),


    path('api/school/settings/', views.create_school_settings, name='create_school_settings'),  # ✅ create
    path('api/school/<str:school_id>/settings/', views.get_school_settings, name='get_school_settings'),
    path('api/school/<str:school_id>/update/', views.update_school_settings, name='update_school_settings'),

    # class management
    path('classes/', views.school_class_list_create, name='class-list-create'),
    path('classes/<int:pk>/', views.school_class_detail, name='class-detail'),

    # section management
    path('sections/', views.section_list_create, name='section-list-create'),
    path('sections/<int:pk>/', views.section_detail, name='section-detail'),

    # attendance management
    path('attendance/mark/', views.mark_attendance_view),
    path('attendance/', views.get_attendance_view),
    # path('attendance/<str:student_id>/<str:date>/', views.delete_attendance_view),
    path('attendance/report/', views.attendance_report_view),  # Get attendance report by student ID and date range
    path('attendance/summary/', views.total_attendance_summary_range_view)  # Get attendance summary by student ID and date range
]