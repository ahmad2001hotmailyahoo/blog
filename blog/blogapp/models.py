from django.db import models

from django.db import models

from django.contrib.auth.models import AbstractBaseUser

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

from django.contrib.auth import get_user_model

class AccountManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username,email ,password,first_name,last_name, **extra_fields):
        
        values = [self, username,email ,password,first_name,last_name]
        field_value_map = dict(zip(self.model.REQUIRED_FIELDS, values))
        for field_name, value in field_value_map.items():
            if not value:
                raise ValueError('The {} value must be set'.format(field_name))

        email = self.normalize_email(email)
        user = self.model(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username,email ,password,first_name,last_name, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username,email ,password,first_name,last_name, **extra_fields)

    def create_superuser(self, email ,password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email ,password, **extra_fields)



class Account(AbstractBaseUser,PermissionsMixin ):
    email = models.EmailField(
        verbose_name = "email address",
        max_length=255,
        unique=True,
    )

    is_staff = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    username = models.TextField(max_length=255)
    first_name = models.TextField(max_length=255)
    last_name = models.TextField(max_length=255)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = AccountManager()
    


class Category(models.Model):
    name = models.CharField(max_length = 255)
    discription  = models.CharField(max_length = 1024)
    email = models.CharField(max_length=1024)
    class Meta:
        ordering = ('-name',)

class Blog_category(models.Model):
    category_title = models.CharField(max_length=255)
    blog_title = models.CharField(max_length=255)
    class Meta:
        ordering = ('-category_title',)

class Blog(models.Model):
    name = models.CharField(max_length=255)
    discription = models.CharField(max_length=1024)
    content = models.CharField(max_length=10024)
    email = models.CharField(max_length=1024)
    class Meta:
        ordering = ('-name',)


class Comment(models.Model):
    user = models.CharField(max_length=255)
    blog_title = models.CharField(max_length=255)
    comment_discription = models.CharField(max_length=1024)

    class Meta:
        ordering = ('-user',)