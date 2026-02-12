from django.urls import path

from analyzer import views

urlpatterns = [
    path("", views.index, name="index"),
    path("analyze", views.analyze, name="analyze"),
    path("results/<str:script_hash>", views.results, name="results"),
]
