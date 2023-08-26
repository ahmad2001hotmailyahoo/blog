from django.urls import path
from .views import RegisterView,getRoutes,create_category,get_category,delete_category,create_blog,delete_blog,get_blog,get_blog_by_title,update_blog,search_blog,create_Comment,get_Comment,top_five_categories,search_blog_cat,count_blog,count_blog_cat,count_blog_search,search_blog_by_title,delete_comment,LginView
urlpatterns = [
    path('',getRoutes),
    path('createCategory',create_category.as_view(),name='create_category'),
    path('register', RegisterView.as_view(),name='register'),
    path('get_category',get_category.as_view(),name="get_category"),
    path('delete_category',delete_category.as_view(),name="delete_category"),
    path('get_blog', get_blog.as_view(),name='get_blog'),
    path('create_blog',create_blog.as_view(),name="create_blog"),
    path('delete_blog',delete_blog.as_view(),name="delete_blog"),
    path('get_blog_title',get_blog_by_title.as_view(),name="get_blog_title"),
    path('update_blog',update_blog.as_view(),name="update_blog"),
    path('search_blog',search_blog.as_view(),name="search_blog"),
    path('comment',create_Comment.as_view(),name="comment"),
    path('get_comment',get_Comment.as_view(),name="get_comment"),
    path('topFiveCategories',top_five_categories.as_view(),name="topFiveCategories"),
    path('search_blog_cat',search_blog_cat.as_view(),name="search_blog_cat"),
    path('count_blog',count_blog.as_view(),name="count_blog"),
    path('search_count_category',count_blog_cat.as_view(),name="count_blog_cat"),
    path('count_blog_search',count_blog_search.as_view(),name="count_blog_search"),
    path('search_blog_by_title',search_blog_by_title.as_view(),name="search_blog_by_title"),
    path('delete_comment',delete_comment.as_view(),name="delete_comment"),
    path('login',LginView.as_view(),name="login")

]