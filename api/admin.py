from django.contrib import admin
from api.models import *

# Register your models here.
admin.site.register(User)
admin.site.register(UniversityName)
admin.site.register(Category)
admin.site.register(Post)
admin.site.register(Event)