from django.urls import path
from .views import *
urlpatterns = [
    path('registration/', userregistration.as_view(), name="registration"), #only for admin
    path('login/', userlogin.as_view(), name="login"),    
    path('logout/', userlogout.as_view(), name="logout"), 
    path('viewprofile/', profileview.as_view(), name="viewprofile"),    # for both supervisor and site engineer 

    path('send_otp/',send_otp,name="sendOtp"),  
    path('confirm_otp/',confirm_otp,name="confirmotp"),
    path('reset_password/',reset_password_view,name="reset_password"),

    path('crew/', crew_list_create, name='crew-list-create'),   #for supervisor can create and get 
    path('crew/<str:crew_id>/', crew_detail_update_delete, name='crew-detail-update-delete'), #for site engineer can get,update,delete

    path('jobs/', job_list_create, name='job-list-create'),
    path('job/<int:id>/', job_detail_update_delete, name='job-detail-update-delete'),

    
    path('add-weekly-log/', add_weekly_log, name='add_weekly_log'),
    path('get-weekly-logs/<int:job_id>/', get_weekly_logs, name='get_weekly_logs'),
    path('get-weekly-logs/<int:job_id>/<int:crew_id>/', get_weekly_logs, name='get_weekly_logs_by_crew'),
    path('job-progress/<int:job_id>/', job_progress, name='job_progress'),

    path('get_available_crews/',get_available_crews, name='get_available_crews')


]