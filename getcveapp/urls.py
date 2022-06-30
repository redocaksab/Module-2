from django.urls import path
from . import views

urlpatterns = [
    path('/all', views.all),
    path('/new', views.new),
    path('/critical', views.critical),
    path('/id', views.byId),
    path('/keyword', views.byKeyword),
    path('/product', views.byProduct),
    path('/pdf/<str:content>', views.downloadAll, name="downloadAll"),
    path('/pdf', views.downloadSearch, name="downloadSearch"),
    path('', views.getSearchResult, name='getSearchResult'),
]
