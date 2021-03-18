from django import forms
from captcha.fields import CaptchaField

class UserForm(forms.Form):
    username = forms.CharField(label="用户名", max_length=128)
    password = forms.CharField(label="密码", max_length=256, widget=forms.PasswordInput)
    captcha = CaptchaField(label='验证码')

class RegisterForm(forms.Form):
    gender = (
        ('male', "男"),
        ('female', "女"),
    )
    username = forms.CharField(label="用户名", max_length=128)
    password1 = forms.CharField(label="密码", max_length=256,widget=forms.PasswordInput)
    password2 = forms.CharField(label="确认密码", max_length=256,widget=forms.PasswordInput)
    email = forms.EmailField(label="邮箱地址", )
    sex = forms.ChoiceField(label='性别', choices=gender)

#class UploadFileForm(forms.Form):
   # title = forms.CharField(max_length=50)
   # file = forms.FileField()

class UploadForm(forms.Form):
    file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={'multiple': True}),  # 支持多文件上传
        label='选择文件...',
        help_text='请注意不要超过最大存储空间'
    )


class Addspace(forms.Form):
    gender=(
        ('KB','KB'),
        ('GB','GB'),
    )
    space_number=forms.IntegerField(label='空间大小',max_value=2147483648)
    space_unit=forms.ChoiceField(label='单位', choices=gender)
    space=forms.CharField(label='空间',max_length=256)

class ForgetForm(forms.Form):

    username = forms.CharField(label="用户名", max_length=128)
    email = forms.EmailField(label="邮箱地址", )

class ChangepwdForm(forms.Form):
    password_old = forms.CharField(label="旧密码", max_length=256,widget=forms.PasswordInput)
    email = forms.EmailField(label="邮箱", )
    password_new = forms.CharField(label="新密码", max_length=256,widget=forms.PasswordInput)
    password_new2 = forms.CharField(label="确认密码", max_length=256,widget=forms.PasswordInput)

"""class SharefileForm(forms.Form):
    code = forms.CharField(label="提取码", max_length=5)
"""

class JoingroupForm(forms.Form):
    group_id = forms.IntegerField(label="组ID")
    code = forms.CharField(label="邀请码" )

class CreateForm(forms.Form):
    groupname = forms.CharField(label="组名", max_length=16)


class ChangegroupnameForm(forms.Form):
    change_groupname = forms.CharField(label="修改组名", max_length=16)