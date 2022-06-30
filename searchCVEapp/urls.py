from getcveapp import views
from django.urls import path, include

urlpatterns = [
    path('', views.index),
    path('info', views.info),
    path('get', include('getcveapp.urls'))
]
