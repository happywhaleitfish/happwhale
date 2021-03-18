from django.urls import path, include
from django.urls import path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from django.contrib import staticfiles
from . import views

urlpatterns = [
    path('index/', views.index),
    path('login/', views.login),
    path('register/', views.register),
    path('logout/', views.logout),
    path('confirm/', views.user_confirm),
    path('forget/', views.forget),
    path('upload/', views.upload_file),
    path('photo/', views.photo),  # 列表
    path('pdf/', views.pdf),
    path('txt/', views.txt),
    path('changepwd/', views.changepwd),
    path('others/', views.others),
    path('download/<id>', views.download, name='download'),  # 下载
    path('delete/<id>', views.delete, name='delete'),  # 删除
    path('leaderdelete/<id>', views.leaderdelete, name='leaderdelete'),
    path('deletemember/<id>', views.deletemember, name='deletemember'),
    path('share/<id>', views.share, name='share'),
    path('captcha/', include('captcha.urls')),
    path('join/', views.joingroup),
    path('search/', views.search, name='search'),
    path('groupfilesearch/', views.groupfilesearch, name='groupfilesearch'),
    path('create/', views.create),
    path('home/', views.home, name='home'),
    path('group/', views.group, name='group'),
    # path('', views.creategroup),
    path('searchgroup/', views.searchgroup, name='searchgroup'),
    path('changegroupname/', views.changegroupname, name='changegroupname'),
    path('dismiss/', views.dismiss, name='dismiss'),
    path('quit/', views.quit, name='quit'),
]
