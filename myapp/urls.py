# myapp/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # 메인 홈
    path('', views.index, name='index'),

    # 보안 취약점 테스트 페이지들
    path('file-upload/', views.file_upload, name='file_upload'),
    path('rxss/', views.rxss, name='rxss'),
    path('image/', views.image_form, name='image_form'),
    path('image/vulnerable/', views.vulnerable_image, name='vulnerable_image'),
    path('image/safe/', views.safe_image, name='safe_image'),
]