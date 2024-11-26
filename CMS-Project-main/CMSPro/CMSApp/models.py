
# Create your models here.
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email,role, name, password=None , password2 =None,): #added name,password2
        """
        Creates and saves a User with the given email, name and password password2.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            name = name,
            role=role,
            
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):  #added name,password2
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password, #added
            name=name, #added 
            #role=role, #added
            
        )
        user.is_admin = True
        user.save(using=self._db)
        return user



class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)  #added
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)    #added
    updated_at = models.DateTimeField(auto_now=True)     #added
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    #profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)

    
    ROLE_CHOICES = [
        ('site_engineer', 'Site Engineer'),
        ('supervisor', 'Supervisor'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES) #added
    
    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]   #edited 

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


#  Crew model-----------------------------------------------------------
import uuid
from django.db import models

# Crew model
class Crew(models.Model):
    name = models.CharField(max_length=100)
    crew_id = models.CharField(max_length=50, unique=True, blank=True, editable=False)  # Unique crew ID, not editable
    is_available = models.BooleanField(default=True)  # Availability status

    def save(self, *args, **kwargs):
        # Generate a unique crew_id if it hasn't been set already
        if not self.crew_id:
            self.crew_id = str(uuid.uuid4())[:8]  # Shorten UUID to 8 characters
            while Crew.objects.filter(crew_id=self.crew_id).exists():
                self.crew_id = str(uuid.uuid4())[:8]
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} (ID: {self.crew_id})"

# Job model--------------------------------------------------------------------------

class Job(models.Model):
    job_order_id = models.CharField(max_length=100, unique=True)  # Unique job order ID
    job_type = models.CharField(max_length=100)  # Type of the job (e.g., 'excavation', 'construction')
    #title = models.CharField(max_length=100)  # Title of the job
    start_date = models.DateField()  # Start date of the job
    end_date = models.DateField()  # End date of the job
    note = models.TextField(blank=True, null=True)  # Additional notes for the job
    crews = models.ManyToManyField(Crew, through='CrewJobAssignment', blank=True)  # Crews assigned to the job

    total_units = models.DecimalField(max_digits=10, decimal_places=2)  # Total units of work
    def __str__(self):
        return self.job_type

# Intermediary model to track assignments of Crews to Jobs
class CrewJobAssignment(models.Model):
    crew = models.ForeignKey(Crew, on_delete=models.CASCADE)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    job_count = models.IntegerField(default=1)  # Tracks how many jobs a crew has worked on

    def save(self, *args, **kwargs):
        # Dynamically calculate job_count for this crew to avoid potential inconsistencies
        self.job_count = CrewJobAssignment.objects.filter(crew=self.crew).count()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Crew: {self.crew.name} - Job: {self.job.job_type}"  



#--------------Weekly logs-------------------------------------------------

from django.db import models
from .models import Job, Crew

class WeeklyLog(models.Model):
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    crew = models.ForeignKey(Crew, on_delete=models.CASCADE, blank=True, null=True)
    date = models.DateField(auto_now_add=True)  # Automatically set to today's date
    units_completed = models.DecimalField(max_digits=5, decimal_places=2)  # E.g., meters dug
    work_notes = models.TextField(blank=True, null=True)  # Optional notes for the week

    def __str__(self):
        return f"Weekly Log: {self.job.job_type} ({self.date})"
