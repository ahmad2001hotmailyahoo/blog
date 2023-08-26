from django.contrib import admin
from .models import Category,Blog_category,Blog,Comment,Account
# Register your models here.

admin.site.register(Category)
admin.site.register(Blog)
admin.site.register(Blog_category)
admin.site.register(Comment)
admin.site.register(Account)