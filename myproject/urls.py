# myproject/urls.py

from django.contrib import admin
from django.urls import include, path
from myapp import views

urlpatterns = [
  path('myapp/', include("myapp.urls")),
  path('admin/', admin.site.urls),
  path('uploads/<str:filename>', views.serve_upload, name='serve_upload'),
  path('execute/', views.execute_file, name='execute_file'),
]