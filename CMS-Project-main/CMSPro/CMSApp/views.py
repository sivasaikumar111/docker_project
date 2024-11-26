

# Create your views here.
from rest_framework.permissions import BasePermission
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import RegistrationSerializer, LoginSerializer, ProfileSerializer , LogoutSerializer,CrewSerializer,JobSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from .password_reset_file import reset_password
from .send_otp_logic import sendOtp
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from .models import Job, Crew, CrewJobAssignment, WeeklyLog
from rest_framework.decorators import api_view, permission_classes
from django.db.models import Sum
from .serializers import WeeklyLogSerializer, JobSerializer



class IsSiteEngineer(BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'site_engineer'
class IsSupervisor(BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'supervisor'

class IsSupervisorOrSiteEngineer(BasePermission):
    def has_permission(self, request, view):
        # Check if the user has either supervisor or site engineer role
        return request.user.role in ['supervisor', 'site_engineer']




def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class userregistration(APIView):
    
    def post(self, request, format=None):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            tokens = get_tokens_for_user(user)
            password = request.data.get("password")  # Assuming password is provided in the request data
            
            # Render the HTML template for the email
            subject = "Welcome to Our Platform!"
            html_content = render_to_string('registration_email.html', {
                'user': user,
                'password': password
            })
            recipient_list = [user.email]
            
            # Create the email message with both HTML and plain text content
            email = EmailMultiAlternatives(subject, "", settings.DEFAULT_FROM_EMAIL, recipient_list)
            email.attach_alternative(html_content, "text/html")
            
            try:
                email.send()
                email_status = "Registration email sent successfully."
            except Exception as e:
                email_status = f"Failed to send registration email: {str(e)}"
            
            return Response({
                'Tokens': tokens,
                'role': user.role,
                'msg': 'Registration successful',
                'email_status': email_status
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class userlogin(APIView):
    def post(self, request, formate=None):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email = email, password=password)
            if user is not None:
                Tokens=get_tokens_for_user(user)
                return Response({'Tokens' :Tokens, 'role': user.role, 'msg': 'login successfull'}, status =status.HTTP_200_OK)
            else:
                return Response({'msg': ['email or password is not valid']},status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)     




class profileview(APIView):
    permission_classes = [IsSupervisorOrSiteEngineer]

    def get(self,request,  formate=None):
        serializer = ProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED) 
    
    def patch(self, request, format=None):
        """
        Partially update the profile of the logged-in user.
        """
        print("patch method called")
        serializer = ProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile updated successfully.", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
class userlogout(APIView):       #here we have to pass access token 
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

#-----------------------reset password---------------------------------------------

@csrf_exempt
@api_view(['POST'])
def send_otp(request):
    email = (json.loads(request.body))['email']
    # email = request.POST["email"]
    
    resp = sendOtp(email)
    return JsonResponse({"message": "OTP sent successfully","status":resp.status_code}, status=status.HTTP_200_OK)

@api_view(['POST'])
def confirm_otp(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    cached_otp = cache.get(email)
    if cached_otp is None or cached_otp != otp:
        return Response({"message": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)

@api_view(['POST'])
def reset_password_view(request):
    email = request.data.get('email')
    password = request.data.get('password')
    confirm_password = request.data.get('confirm_password')

    result = reset_password(email, password, confirm_password)  
    return result 


#---------------------- Crew view----------------------------------------------



@api_view(['GET', 'POST'])
@permission_classes([IsSupervisor])
def crew_list_create(request):
    if request.method == 'GET':
        crews = Crew.objects.all()
        serializer = CrewSerializer(crews, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    elif request.method == 'POST':
        serializer = CrewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsSiteEngineer])
def crew_detail_update_delete(request, crew_id):
    try:
        crew = Crew.objects.get(crew_id=crew_id)
    except Crew.DoesNotExist:
        return Response({'error': 'Crew not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = CrewSerializer(crew)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        serializer = CrewSerializer(crew, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        crew.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
#-------------------Jobs view ----------------------------

# views.py


@api_view(['GET', 'POST'])
@permission_classes([IsSupervisorOrSiteEngineer])
def job_list_create(request):
    if request.method == 'GET':
        jobs = Job.objects.all()
        serializer = JobSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    elif request.method == 'POST':
        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            job = serializer.save()
            # Get and deduplicate the crews list
            crews = set(request.data.get('crews', []))  # Convert to set to remove duplicates    
            # Create CrewJobAssignment entries without duplicates
            for crew_id in crews:
                try:
                    crew = Crew.objects.get(id=crew_id)
                    # Use get_or_create to avoid creating duplicates
                    CrewJobAssignment.objects.get_or_create(job=job, crew=crew)
                except Crew.DoesNotExist:
                    # Handle the case if crew_id is invalid
                    return Response({"error": f"Crew with id {crew_id} does not exist."}, status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsSiteEngineer])
def job_detail_update_delete(request, id):
    try:
        job = Job.objects.get(id=id)
    except Job.DoesNotExist:
        return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = JobSerializer(job)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        serializer = JobSerializer(job, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        job.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



#-------------------weeklylog view -----------------------------





@api_view(['POST'])
@permission_classes([IsSupervisor])
def add_weekly_log(request):
    """
    Add or update a weekly log.
    """
    data = request.data
    job_id = data.get('job_id')
    crew_id = data.get('crew_id')
    units_completed = data.get('units_completed', 0)
    work_notes = data.get('work_notes', "")

    try:
        job = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)

    try:
        crew = Crew.objects.get(id=crew_id)
    except Crew.DoesNotExist:
        return Response({"error": "Crew not found."}, status=status.HTTP_404_NOT_FOUND)

    # Create or update the weekly log
    weekly_log, created = WeeklyLog.objects.get_or_create(
        job=job,
        crew=crew,
        defaults={'units_completed': units_completed, 'work_notes': work_notes}
    )

    if not created:
        weekly_log.units_completed = units_completed
        weekly_log.work_notes = work_notes
        weekly_log.save()

    serializer = WeeklyLogSerializer(weekly_log)
    return Response(serializer.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsSiteEngineer])
def get_weekly_logs(request, job_id, crew_id=None):
    """
    Fetch weekly logs for a job and optionally filter by crew.
    """
    try:
        job = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)

    filters = {'job': job}
    if crew_id:
        filters['crew__id'] = crew_id

    weekly_logs = WeeklyLog.objects.filter(**filters).order_by('date')
    serializer = WeeklyLogSerializer(weekly_logs, many=True)

    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsSiteEngineer])
def job_progress(request, job_id):
    """
    Get the percentage of work done and pending for a specific job.
    """
    try:
        job = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)

    total_units_completed = WeeklyLog.objects.filter(job=job).aggregate(Sum('units_completed'))['units_completed__sum'] or 0

    if job.total_units <= 0:
        return Response({"error": "Invalid total units for the job."}, status=status.HTTP_400_BAD_REQUEST)

    work_done_percentage = (total_units_completed / job.total_units) * 100
    work_pending_percentage = 100 - work_done_percentage

    if work_done_percentage > 100:
        work_done_percentage = 100
        work_pending_percentage = 0

    return Response({
        "job_id": job.id,
        "job_type": job.job_type,
        "total_units": job.total_units,
        "units_completed": total_units_completed,
        "work_done_percentage": round(work_done_percentage, 2),
        "work_pending_percentage": round(work_pending_percentage, 2),
        "status": "Completed" if work_done_percentage == 100 else "In Progress"
    }, status=status.HTTP_200_OK)



@api_view(['GET'])
@permission_classes([IsSupervisorOrSiteEngineer])
def get_available_crews(request):
    # Filter crews with is_available set to True
    available_crews = Crew.objects.filter(is_available=True)
    serializer = CrewSerializer(available_crews, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


