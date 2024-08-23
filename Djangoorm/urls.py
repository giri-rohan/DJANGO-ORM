"""
URL configuration for Djangoorm project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from drf_yasg.generators import OpenAPISchemaGenerator
from rest_framework import permissions


class BothHttpAndHttpsSchemaGenerator(OpenAPISchemaGenerator):
    '''swagger scheme generator'''

    def get_schema(self, request=None, public=False):
        schema = super().get_schema(request, public)
        schema.schemes = ["http", "https",]
        return schema

SchemaView = get_schema_view(
    openapi.Info(
        title="Djangoorm Api List",
        default_version='v1',
    ),  
    public=True,
    generator_class=BothHttpAndHttpsSchemaGenerator,
    permission_classes=[permissions.AllowAny],
)

class Version2SchemaGenerator(BothHttpAndHttpsSchemaGenerator):
    '''Schema generator for API version 2'''

    def get_schema(self, request=None, public=False):
        schema = super().get_schema(request, public)
        schema.info.version = 'v2'
        return schema

SchemaViewV2 = get_schema_view(
    openapi.Info(
        title="Django ORM API",
        default_version='v2',
        description="API documentation for version 2",
    ),
    public=True,
    generator_class=Version2SchemaGenerator,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('swagger/', SchemaView.with_ui('swagger',
         cache_timeout=0), name='schema-swagger-ui'),
    path('swagger/v2/', SchemaViewV2.with_ui('swagger', cache_timeout=0), name='swagger-v2'),
]
