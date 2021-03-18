from django.contrib import admin

# Register your models here.
from . import models

admin.site.register(models.User)
admin.site.register(models.File)
admin.site.register(models.ConfirmString)
admin.site.register(models.Group)