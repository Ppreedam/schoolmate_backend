from . import views
from schoolmate_backend.urls import path



urlpatterns = [
    # Schoolmate_UserAuth
    path("test/", views.test_app_view, name="get_app"),
    path("signup/", views.user_registrations_views, name="user_registration"),
    path("signin/", views.user_login_view, name="user_login"),
    path("profile/", views.user_profile_view, name="user_profile"),
    path("logout/", views.user_logout_view, name="user_logout"),
    # create school
    path("create/school/", views.create_school_view, name="create_school"),
    path("schools/", views.list_schools, name="list_schools"), # list all schools
    path("school/<int:pk>/", views.get_school, name="get_school"), # get school by id
    path("update/school/<int:pk>/", views.update_school, name="update_school"), # update school by id
    path("delete/school/<int:pk>/", views.delete_school, name="delete_school"), # delete school by id

    # create student
    path('students/', views.get_all_students, name='get_all_students'),
    path('students/create/', views.create_student, name='create_student'),
    path('students/<int:student_id>/', views.get_student, name='get_student'),
    path('students/<int:student_id>/update/', views.update_student, name='update_student'),
    path('students/<int:student_id>/delete/', views.delete_student, name='delete_student'),

    # Fee Structure
    path('fees/create/', views.create_fee_structure, name='create_fee_structure'),
    path('fees/', views.get_fee_structures_by_school, name='get_fee_structures_by_school'),
    path('fees/<int:fee_id>/', views.get_fee_structure_by_id, name='get_fee_structure_by_id'),
    path('fees/<int:fee_id>/update/', views.update_fee_structure, name='update_fee_structure'),
    path('fees/<int:fee_id>/delete/', views.delete_fee_structure, name='delete_fee_structure')
    
]