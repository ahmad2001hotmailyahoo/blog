from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
# from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate,login
from django.contrib.auth.models import User
from django.db import models
from .models import Category,Blog,Blog_category,Comment,Account
from django.db.models import Count
from django.core.paginator import Paginator
import math
from django.core.validators import validate_email

from django.http import JsonResponse
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import exceptions


import datetime
import jwt
from django.conf import settings
from rest_framework import serializers

def generate_access_token(user):

    access_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
        'iat': datetime.datetime.utcnow(),
    }
    access_token = jwt.encode(access_token_payload,
                              settings.SECRET_KEY, algorithm='HS256').encode('utf-8')
    return access_token


def generate_refresh_token(user):
    refresh_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }
    refresh_token = jwt.encode(
        refresh_token_payload, settings.REFRESH_TOKEN_SECRET, algorithm='HS256').encode('utf-8')

    return refresh_token



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id', 'username', 'email',
                  'first_name', 'last_name', 'is_staff','is_admin']


class LginView(APIView):
    def post(self,request):
        username = request.data["username"]
        password =request.data["password"]
        print(password)
        response = Response()
        user = Account.objects.filter(username=username).first()
        if(user is None):
            return Response('user not found')
        if (not user.check_password(password)):
            return Response('wrong password')

        serialized_user = UserSerializer(user).data


        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
        response.data = {
        'access_token': access_token,
        'user': serialized_user,
        }

        response.template_name="login.html"

        return response




class RegisterView(APIView):
    def post(self,request):
        getting_user =  Account.objects.filter(username=request.data["username"]).first()
        if getting_user == None:
            print(".............Creating.........User............")
        else:
            return Response("user already exits")

        # if request.method == "POST":
        password = request.data["password"]
        username= request.data["username"]
        firstname = request.data["firstname"]
        lastname = request.data["lastname"]
        print(username)
        if(username == "" and password==""):
            return Response("provide username and password")
        if(len(password) < 8):
            return Response("password must be 8 digits long")
        try:
            validate_email(username)
            valid_email = True
            print(valid_email)
        except:
            # except validate_email:
            valid_email = False
            return Response("not a valid email")

        user = Account.objects.create_user(username=username,email=username,password=password,first_name=firstname,last_name=lastname,is_staff=False,is_admin=False)
        user.save()
        # user = authenticate(username=username,password=password)
        # login(request,user)
        return Response(username)

            


class create_category(APIView):
    def post(self,request):
        getting_category =  Category.objects.filter(name=request.data["cat_title"]).first()
        if (request.data['user'] == '' and request.data['user'] == None):
            return Response('not autorized')
        if getting_category == None:
            print(".............Creating.........Category............")
        else:
            return Response("category already exits")
        
        print(request.method)
        if request.method == "POST":
            category_title = request.data["cat_title"]
            category_disc = request.data["cat_desc"]
            user = request.data["user"]
            print(type(user))
            cat = Category.objects.create(name=category_title,discription= category_disc,email=user)
            cat.save()
            

        user = Category.objects.all()
        new_array =[]
        i = 0
        for users in user:
            i =0
            new_array.append([users.email,users.discription,users.name])

        print(new_array)

        return Response({"user":new_array})
        # return Response("post not allowed")
    

class get_category(APIView):
    def post(self,request):
        user = Category.objects.all()
        new_array =[]
        i = 0
        for users in user:
            i =0
            new_array.append([users.email,users.discription,users.name])

        print(new_array)

        return Response({"user":new_array})
    
class delete_category(APIView):
    def post(self,request):
        if (request.data['user'] == '' and request.data['user'] == None):
            return Response('not autorized')
        get_caterory_1 = request.data['cat_title']
        print('get_category',get_caterory_1)
        category_to_deleted = Category.objects.filter(name=get_caterory_1)
        blog_category = Blog_category.objects.filter(category_title=get_caterory_1)
        new_array =[]        
        # print(category_to_deleted.__dict__)
        # print(category_to_deleted.email)
        try:
            print(category_to_deleted.first().email == request.data['user'])
            if(category_to_deleted.first().email == request.data['user']):
                category_to_deleted.delete()
                blog_category.delete()
                Category.save()
                Blog_category.save()
                

                

                i = 0
                for users in user:
                    new_array.append([users.email,users.discription,users.name])

                print(new_array)

                return Response({"user":new_array})
        except:
            user = Category.objects.all()
            for users in user:
                new_array.append([users.email,users.discription,users.name])

            print(new_array)

            return Response({"user":new_array})

        finally:
            user = Category.objects.all()
            for users in user:
                new_array.append([users.email,users.discription,users.name])

            print(new_array)

            return Response({"user":new_array})

        # user = Category.objects.all()
        # for users in user:
        #     new_array.append([users.email,users.discription,users.name])

        # print(new_array)

        # return Response({"user":new_array})
    



class create_blog(APIView):
    def post(self,request):
        blog_title = request.data['blog_title']
        blog_disc = request.data['blog_disc']
        blog_content = request.data['blogcontent']
        print(blog_content)
        blog_categories_1 = request.data['categories']
        user_email = request.data['user']
        cat_1 = blog_categories_1
        if (request.data['user'] == '' and request.data['user'] == None):
            return Response('not autorized')

        getting_blog =  Blog.objects.filter(name=request.data["blog_title"]).first()
        if getting_blog == None and user_email != None:
            print(".............Creating.........Blog............")
        else:
            return Response("Blog already exits")
        

        blog = Blog.objects.create(name=blog_title,discription= blog_disc,content = blog_content,email=user_email)
        blog.save()
        print(blog_categories_1)
        for element in blog_categories_1:
            # print(1)
            blog_category1 =  Blog_category.objects.create(category_title=element,blog_title=blog_title)
            blog_category1.save()
        
        # print(blog_content)
        arr = [blog.id,blog_title,blog_disc,blog_content,cat_1,user_email]
        
        return Response(arr)
        



class delete_blog(APIView):
    def post(self,request):
        # if request.data["user"] == "" and request.data["user"] == None:
            # return Response("not authorized")
        blog_to_be_deleted = request.data['blog_title']
        # print(blog_to_be_deleted)
        try:
            if Blog.objects.filter(name=blog_to_be_deleted).first().email == request.data["user"]:
                delete_blog = Blog.objects.filter(name=blog_to_be_deleted).delete()
                dete_Category_blog = Blog_category.objects.filter(blog_title=blog_to_be_deleted)
                comments = Comment.objects.filter(blog_title=blog_to_be_deleted)

                for i in dete_Category_blog:
                    i.delete()
                for i in comments:
                    i.delete()
                
                dete_Category_blog.save()
                comments.save()
                # print(delete_blog)
                # print(dete_Category_blog)
                return Response("blog deleted")
            else:
                return ("not authorized") 


        finally:
            return Response("blog can't be deleted")



class get_blog(APIView):
    def post(self,request):


        blog_arr= []
        cat_arr = []
        user = Blog.objects.all()
        paginator = Paginator(user, 6)
        page_number = request.data["page"]
        page_obj = paginator.get_page(request.data["page"])
        prev = False
        next = False
        # print("--PAGE__")
        # print(page_obj)

        for uses in page_obj:
            cat_arr=[]
            cat = Blog_category.objects.filter(blog_title=uses.name)
            for cats in cat:
                cat_arr.append(cats.category_title)
            if cat_arr == []:
                uses.delete()
            else:
                blog_arr.append([uses.email,uses.name,uses.discription,uses.content,set(cat_arr),uses.id])        
            print(blog_arr)



        print(blog_arr)
        return Response(blog_arr)


class get_blog_by_title(APIView):
    def post(self,request):
        blog = Blog.objects.filter(name=request.data['blog_title']).first()
        blog_category = Blog_category.objects.filter(blog_title=request.data['blog_title'])
        blog_cat_arr = []
        for i in blog_category:
            blog_cat_arr.append(i.category_title)
        blog_arr = [blog.name,blog.discription,blog_cat_arr]
        print("'blog_id'")
        print(blog.__dict__)
        print("'arr'")
        print(blog_arr)
        return Response(blog_arr)

class update_blog(APIView):
    def post(self,request):
        # print(request.data["user"])
        if request.data["user"] == '' and request.data['user'] == None:
            return Response("not authorized")
        
        print(request.data["prev_blog_title"])
        try:
            update_blog = Blog.objects.filter(name=request.data["prev_blog_title"]).first()
            if request.data["user"] != update_blog.email:
                return Response("not authorized")
            else:


                title = update_blog.name
                update_blog.name = request.data["blog_title_update"]
                update_blog.discription = request.data["blog_desc_update"]
                update_blog.content = request.data["blog_Content"]
                update_blog.save()

            dete_Category_blog = Blog_category.objects.filter(blog_title=update_blog.name)
            for i in dete_Category_blog:
                i.delete()

        
        
            for j in request.data["blog_desc_categories_update"]:
                category_blog_create = Blog_category.objects.create(blog_title=update_blog.name,category_title=j)
                category_blog_create.save()
                 


            return Response(request.data)
        finally:
            return Response("can;t be updated")
    


class top_five_categories(APIView):
    def post(self,request):
            print(1)
            blog_cat_arr = ["A","V","X"]
            # blog_category = Blog_category.objects.annotate(num_Category=Count('category_title'))

            blog_category_1 = Blog_category.objects.values("category_title").order_by().annotate(Count('category_title'))
            blog_category_2 = blog_category_1.order_by("category_title__count").reverse()[:5]
            # print("top_five_categories")
            # print(len(blog_category_2))
            # print(blog_category_2[0]['category_title'])
            category_set = []
            i = 0 
            for i in range(0,len(blog_category_2)):
                category_set.append(blog_category_2[i]['category_title'])
            # print(category_set)
            return Response(category_set)    
    
        

    
class create_Comment(APIView):
    def post(self,request):
        if request.data['user'] != '' and request.data['user'] != None:
            comment = Comment.objects.create(user=request.data['user'],blog_title=request.data['blogTitle'],comment_discription=request.data['comment'])
            comment.save()
            return Response("comment created") 
        return Response(request.data)
    
class get_Comment(APIView):
    def post(self,request):
        comments = Comment.objects.all()
        comment_Arr = []
        for comment in comments:
            print(comment.user)
            print(comment.blog_title)
            print(comment.comment_discription)
            comment_Arr.append([comment.user,comment.blog_title,comment.comment_discription])
        
        print(comment_Arr)
        return Response(comment_Arr)
    

class search_blog_cat(APIView):
    def post(self,request):
        print(request.data['cat'])

        blog_category = Blog_category.objects.filter(category_title__in = request.data['cat'])
        blogs_title_arr = []
        blogging_arr = []
        for i in blog_category:
            blogs_title_arr.append(i.blog_title)
        blogs_title_arr = set(blogs_title_arr)

        blog = Blog.objects.filter(name__in = blogs_title_arr)
        paginator = Paginator(blog, 6)
        page_number = request.data['page']
        print("page_number")
        print(page_number)
        page_obj = paginator.get_page(page_number)
        blog_cat_arr = []
        print("search_blog_cat")
        print(page_obj)

        for uses in page_obj:
            cat_arr = []
            print(uses)
            cat = Blog_category.objects.filter(blog_title=uses.name)
            blog = Blog.objects.filter(name=uses.name).first()
            for cats in cat:
                cat_arr.append(cats.category_title)
            
            c = [blog.email,blog.name,blog.content,blog.discription,cat_arr,blog.id]
            blogging_arr.append(c)


        return Response(blogging_arr)
    
            

class count_blog(APIView):
    def post(self,request):
        no_of_blogs = Blog.objects.all().count()
        # print(math.ceil(no_of_blogs/6))
        return Response(math.ceil(no_of_blogs/6))
    
class count_blog_cat(APIView):
    def post(self,request):
        no_of_blogs = Blog_category.objects.filter(category_title__in=request.data["cat"])
        arr =[]
        for i in no_of_blogs:
            arr.append(i.blog_title)
        arr = set(arr)
        print(len(arr))
        return Response(math.ceil(len(arr)/6))
    

class search_blog_by_title(APIView):
    def post(self,request):
            # blog_category = Blog.objects.filter(name=request.data["search"])
            # print(request.data['search'])
            # blog_cat_arr = []
            # print("search_blog_cat")
            # print(page_obj)

            # for blogs in page_obj:
                # blog_cat_arr.append(page.blog)
            # print(blog_category)
            # for blogs in blog_category:
                # blog_cat_arr.append(blogs.name) 


            # print(blog_cat_arr)

            # blogging_arr = []
            # cat_arr = []
            # cat_arr = []
            # print(1)
            # for uses in blog_cat_arr:
            cat_arr = []
            blogging_arr = []
            print(request.data["search"])
            blog = Blog.objects.filter(id=request.data["search"]).first()
            cat = Blog_category.objects.filter(blog_title=blog.name)
            print("arr-112323s")
            print(blog.id)
            for cats in cat:
                cat_arr.append(cats.category_title)
            blogging_arr.append([blog.email,blog.name,blog.content,blog.discription,cat_arr,blog.id])

            print('arr')
            print(len(blogging_arr))
            return Response(blogging_arr)
    

class search_blog(APIView):
    def post(self,request):
                    # print(request.data['cat'])
        if(request.data['category'] == None or request.data['category'] == []):
            blog_category = Blog.objects.filter(name__icontains=request.data['search'])

            paginator = Paginator(blog_category, 6)
            page_number = request.data['page']
            # print("page_number")
            # print(page_number)
            page_obj = paginator.get_page(page_number)
            print("pageNumber")
            print(page_number)
            blog_cat_arr = []
            # print("search_blog_cat")
            # print(page_obj)

            # for blogs in page_obj:
                # blog_cat_arr.append(page.blog)
            for blogs in page_obj:
                blog_cat_arr.append(blogs.name) 


            blog_cat_arr = set(blog_cat_arr)
            # print(blog_cat_arr)

            blogging_arr = []
            cat_arr = []
            cat_arr = []
            print(1)
            for uses in blog_cat_arr:
                cat_arr = []
                blog = Blog.objects.filter(name=uses).first()
                cat = Blog_category.objects.filter(blog_title=blog.name)
                
                for cats in cat:
                    cat_arr.append(cats.category_title)
                blogging_arr.append([blog.email,blog.name,blog.content,blog.discription,cat_arr])

            print('arr')
            print(len(blogging_arr))
            return Response(blogging_arr)
        else:
            blog_category = Blog_category.objects.filter(category_title__in = request.data['category'],blog_title__icontains=request.data['search'])
            blogs_title_arr = []
            blogging_arr = []
            for i in blog_category:
                blogs_title_arr.append(i.blog_title)
            blogs_title_arr = set(blogs_title_arr)

            blog = Blog.objects.filter(name__in = blogs_title_arr)
            paginator = Paginator(blog, 6)
            page_number = request.data['page']
            print("page_number")
            print(page_number)
            page_obj = paginator.get_page(page_number)
            blog_cat_arr = []
            print("search_blog_cat")
            print(page_obj)

            for uses in page_obj:
                cat_arr = []
                print(uses)
                cat = Blog_category.objects.filter(blog_title=uses.name)
                blog = Blog.objects.filter(name=uses.name).first()
                for cats in cat:
                    cat_arr.append(cats.category_title)
            
                c = [blog.email,blog.name,blog.content,blog.discription,cat_arr,blog.id]
                blogging_arr.append(c)

            return Response(blogging_arr)
        

class count_blog_search(APIView):
    def post(self,request):
        print(request.data['category'])
        if(request.data['category'] == None or request.data['category'] == []):
            no_of_blogs = Blog.objects.filter(name__icontains=request.data["search"]).count()
            print(no_of_blogs/6)
            return Response(math.ceil(no_of_blogs/6))
        else:
            no_of_blogs = Blog_category.objects.filter(blog_title__icontains=request.data["search"],category_title__in=request.data["category"])
            arr = []
            for i in no_of_blogs:
                number = Blog.objects.filter(name=i.blog_title)
            arr=set(arr)
            print(len(arr))
            return Response(math.ceil(len(arr)/6))

class delete_comment(APIView):
    def post(self,request):
        try :
            comment = Comment.objects.filter(comment_discription=request.data["disc"]).first().delete()
        finally:
            return Response("deleted")

@api_view(['POST'])
def getRoutes(request):
    routes = [
        '/register',
        '/createCategory',
        '/get_category',
        '/delete_category',
        '/create_blog',
        '/get_blog',
        '/get_blog_title',
        '/delete_blog',
        '/comment',
        '/get_comment',
        '/update_blog',
        '/search_blog',
        '/topFiveCategories',
        '/search_blog_cat',
        '/count_blog',
        '/search_count_category',
        '/count_blog_search',
        '/search_blog_by_title',
        '/delete_comment',
        '/login',
    ]

    return Response(routes)