import datetime
import hashlib
import json
import os
import random
# Create your views here.
import re
import shutil

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from account import File_safestorage, Exchange, secret_key_rsa
from . import forms
from . import models
from .forms import UploadForm
from .models import File, Group, User

the_salt = "my_salt"


def index(request):  # 主页
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(f_owner=user_name)
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/index.html',
                  {'file_infos': file_infos, 'spaceprecent': spaceprecent, 'used': used, 'max': max,
                   'scaling': scaling})


@csrf_exempt
def login(request):  # 登录
    if request.session.get('is_login', None):
        return redirect('/index/')
    if request.method == "POST":
        message = '请检查填写内容'
        username = request.POST.get('username')
        """print(username)
        username = Exchange.decrypt(username).decode()
        print(username)"""
        password = request.POST.get('password')
        """print(password)
        password = Exchange.decrypt(password).decode()
        print(password)"""
        try:
            user = models.User.objects.get(name=username)
        except:
            message = '用户不存在'
            return render(request, 'account/login.html', locals())

        if not user.has_confirmed:
            message = '该用户还未经过邮件确认！'
            return render(request, 'account/login.html', locals())

        if user.password == hash_code(password):  # 比对密码。
            Exchange.service()
            request.session['is_login'] = True
            request.session['user_id'] = user.id
            request.session['user_name'] = user.name
            return redirect('/index/')
        else:
            message = '密码不正确'
            return render(request, 'account/login.html', locals())
    login_form = forms.UserForm()
    return render(request, 'account/login.html', locals())


def register(request):  # 注册
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        message = "请检查填写的内容！"
        username = request.POST.get('username')
        password1 = request.POST.get('password1')  # 解密之后都叫_之前的名字
        password2 = request.POST.get('password2')
        email = request.POST.get('email')
        # sex = request.POST.get('sex')
        # 把各个信息解密
        if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) == None:
            message = '邮箱格式错误'  # 正则匹配邮箱格式，错误则返回提示信息
            return render(request, 'account/register.html', locals())
        if len(str(password1)) < 6:
            message = '密码长度不得小于6位啊亲'
            return render(request, 'account/register.html', locals())
        elif password1 != password2:
            message = '两次输入的密码不同！'
            return render(request, 'account/register.html', locals())
        else:
            same_name_user = models.User.objects.filter(name=username)
            if same_name_user:
                message = '用户名已经存在'
                return render(request, 'account/register.html', locals())
            same_email_user = models.User.objects.filter(email=email)
            if same_email_user:
                message = '该邮箱已经被注册了！'
                return render(request, 'account/register.html', locals())
            # 发邮件

            new_user = models.User()
            new_user.name = username
            new_user.password = hash_code(password1)
            new_user.email = email
            # new_user.sex = sex
            new_user.file_url = "127.0.0.1:8000/static/file/" + username
            new_user.save()
            os.makedirs("E:\\upload\\" + username)
            request.session['user_name'] = new_user.name
            code = make_confirm_string(new_user)
            send_email(email, code)
            message = '请前往邮箱进行确认！'
            return render(request, 'account/confirm.html', locals())
    return render(request, 'account/register.html', locals())


def changepwd(request):  # 修改密码
    if not request.session.get('is_login', None):
        return redirect('/login/')
    if request.method == 'POST':

        message = "请检查填写的内容！"
        password_old = request.POST.get('password_old')
        email = request.POST.get('email')
        password_new = request.POST.get('password_new')
        password_new2 = request.POST.get('password_new2')

        if len(str(password_new)) < 6:
            message = '密码长度不得小于6位啊亲'
            return render(request, 'account/changepwd.html', locals())
        elif password_new != password_new2:
            message = '两次输入的密码不同！'
            return render(request, 'account/changepwd.html', locals())
        else:
            changer_name = request.session.get('user_name')
            user = models.User.objects.get(name=changer_name)

            if user.email != email:
                message = '您的邮箱错误！'
                return render(request, 'account/changepwd.html', locals())

            if user.password != hash_code(password_old):
                message = '原密码错误！'
                return render(request, 'account/changepwd.html', locals())

            user.password = hash_code(password_new)
            user.save()
            return redirect('/login/')
    return render(request, 'account/changepwd.html', locals())


def logout(request):  # 登出
    if not request.session.get('is_login', None):
        return redirect("/login/")

    request.session.flush()
    return redirect("/login/")


def make_confirm_string(user):  # 构造注册时的邮箱确认码
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code = hash_code(user.name, now)
    models.ConfirmString.objects.create(code=code, user=user, )
    return code


def send_email(email, code):  # 注册时的邮箱确认邮件发送函数

    from django.core.mail import EmailMultiAlternatives

    subject = '来自安全磁盘的注册确认邮件'

    text_content = '''感谢注册安全磁盘，\
                    如果你看到这条消息，说明你的邮箱服务器不提供HTML链接功能，请联系管理员！'''

    html_content = '''
                    <p>感谢注册安全磁盘,\
                    这里是<a href="http://{}/confirm/?code={}" target=blank>激活入口</a>！</p>
                    <p>请点击激活入口完成注册确认！</p>
                    <p>此链接有效期为7天！</p>
                    '''.format('10.122.244.180:8000', code, settings.CONFIRM_DAYS)

    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def user_confirm(request):  # 用户确认页面
    code = request.GET.get('code', None)
    message = ''
    try:
        confirm = models.ConfirmString.objects.get(code=code)
    except:
        message = '无效的确认请求!'
        return render(request, 'account/confirm.html', locals())

    c_time = confirm.c_time
    now = datetime.datetime.now()
    if now > c_time + datetime.timedelta(settings.CONFIRM_DAYS):
        confirm.user.delete()
        message = '您的邮件已经过期！请重新注册!'
        return render(request, 'account/confirm.html', locals())
    else:
        confirm.user.has_confirmed = True
        confirm.user.save()
        confirm.delete()
        message = '感谢确认，请使用账户登录！'
        return render(request, 'account/confirm.html', locals())


def hash_code(s, salt='mysite'):  # 用来复制构造确认码
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())
    return h.hexdigest()


def code():  # 构造邀请码
    list_num = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    list_str = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 's', 't', 'x', 'y',
                'z']
    veri_str = random.sample(list_str, 2)
    veri_num = random.sample(list_num, 2)
    veri_out = random.sample(veri_num + veri_str, 4)
    veri_res = str(veri_out[0]) + str(veri_out[1]) + str(veri_out[2]) + str(veri_out[3])
    return veri_res


def forget(request):  # 忘记密码
    if request.method == 'POST':

        message = "请检查填写的内容！"
        username = request.POST.get('username')
        email = request.POST.get('email')
        if not models.User.objects.filter(name=username).exists():
            message = '用户名不存在'
            return render(request, 'account/forget.html', locals())
        user = models.User.objects.get(name=username)
        if email != user.email:
            message = '邮箱错误'
            return render(request, 'account/forget.html', locals())
        new_password = password()
        user.password = hash_code(new_password)
        user.save()
        send_email_forget(email, new_password)
        message = '请前往邮箱进行确认！'
        return render(request, 'account/confirm.html', locals())

    return render(request, 'account/forget.html', locals())


def send_email_forget(email, password):  # 忘记密码时重置密码的邮件发送函数

    from django.core.mail import EmailMultiAlternatives

    subject = '来自<<安全磁盘>>的密码重置邮件'

    text_content = '''感谢使用<<安全磁盘>>，\
                    如果你看到这条消息，说明你的邮箱服务器不提供HTML链接功能，请联系管理员！'''

    html_content = '''
                    <p>感谢使用安全磁盘,\
                    这里是<a href="http://{}/login" target=blank>登录入口</a>！</p>
                    <p>检查到您的账户刚刚进行了密码重置,</p>
                    <p>您更改后的有效密码是{}</p>
                    '''.format('127.0.0.1:8000', password, settings.CONFIRM_DAYS)

    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def password():  # 构造六位临时密码
    list_num = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    list_str = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 's', 't', 'x', 'y',
                'z']
    veri_str = random.sample(list_str, 3)
    veri_num = random.sample(list_num, 3)
    veri_out = random.sample(veri_num + veri_str, 6)
    veri_res = str(veri_out[0]) + str(veri_out[1]) + str(veri_out[2]) + str(veri_out[3]) + str(veri_out[4]) + str(
        veri_out[5])
    return veri_res


def home(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    email = user.email
    used_space = user.max_space - user.remain_space
    used = round(used_space / 1048576, 2)
    remain = round(user.remain_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    if user.group == None:
        group = "您还未创建或加入任何组别。"
        permission = ""
        groupname = ""
    else:
        group = user.group.id
        groupname = user.group.g_name
        if user.permission:
            permission = "组长"
        else:
            permission = "组员"
    return render(request, 'account/home.html',
                  {'groupname': groupname, 'used': used, 'max': max, 'username': user_name, 'email': email,
                   'permission': permission, 'group': group})


def group(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    if user.group == None:
        return HttpResponseRedirect('/home/')
    else:
        group = user.group
        name = user.group.g_name
        file_infos = File.objects.filter(f_group=user.group.id)
        member_infos = User.objects.filter(group=user.group)
        if user.permission == True:
            message = "邀请码：" + group.g_code
            return render(request, 'account/leadergroup.html',
                          {'file_infos': file_infos, 'member_infos': member_infos, 'message': message, 'name': name})
        else:
            message = "您的身份是该组的成员。您有对文件的分享和下载权限。"
            return render(request, 'account/notleadergroup.html',
                          {'file_infos': file_infos, 'member_infos': member_infos, 'message': message, 'name': name})


def share(request, id):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    if user.group == None:
        return redirect('/index/')
    sharefile = File.objects.get(id=id)
    owner = sharefile.f_owner
    user = User.objects.get(name=owner)
    sharefile.f_group = user.group.id
    sharefile.save()

    alllist = os.listdir(u"E:\\upload\\" + user.name)
    # alllist = os.listdir(u"E:\\upload")
    for i in alllist:
        if sharefile.f_name in i:
            oldname = u"E:\\upload\\" + user.name + "\\" + sharefile.f_name
            # oldname = u"E:\\upload\\"  + sharefile.f_name
            newname = u"E:\\upload\\group\\" + user.group.g_name + "\\" + sharefile.f_name
            # os.makedirs(newname)
            shutil.copyfile(oldname, newname)

    return redirect('/index/')


def search(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    q = request.GET.get('key')
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(Q(f_name__icontains=q) & Q(f_owner=user_name))
    return render(request, 'account/index.html', {'file_infos': file_infos})


def groupfilesearch(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    q = request.GET.get('key')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    group = user.group.id
    file_infos = File.objects.filter(Q(f_name__icontains=q) & Q(f_group=group))
    return render(request, 'account/leadergroup.html', {'file_infos': file_infos})


def searchgroup(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    q = request.GET.get('key')
    group_infos = Group.objects.filter(
        Q(g_owner__icontains=q) | Q(id__icontains=q) | Q(g_name__icontains=q) | Q(email__icontains=q) | Q(
            number__icontains=q))
    return render(request, 'account/joingroup.html', {'group_infos': group_infos})


"""def shareFile(request,id):#文件分享
    sharefile = File.objects.get(id=id)
    owner = sharefile.f_owner
    if request.method == "POST":
        sharefile_form=forms.SharefileForm(request.POST)
        message='请检查填写内容'

        if sharefile_form.is_valid():#验证表单
            code = sharefile_form.cleaned_data.get('code')
            if sharefile.f_code != code:
                message = '提取码错误！'
                return render(request,'account/share.html',{"id":id,"message":message,"sharefile_form":sharefile_form,"owner":owner})
            else:
                return redirect('/download/'+id)
        else:
            return render(request, 'account/share.html',{"id":id,"message":message,"sharefile_form":sharefile_form,"owner":owner})
    sharefile_form = forms.SharefileForm()  # 如果验证没有通过，可以返回一个空表单
    return render(request, 'account/share.html',{"id":id,"sharefile_form":sharefile_form,"owner":owner})"""


def create(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)

    if request.method == "POST":

        message = '请检查填写内容'
        groupname = request.POST.get('groupname')

        if models.Group.objects.filter(g_name=groupname).exists():
            message = '该组名已存在！'
            return render(request, 'account/create.html', {"message": message, "create_form": create_form})
        if user.group != None:
            if user.permission == True:
                message = "您已创建过成员组"
            else:
                message = "您已加入过成员组"
            return render(request, 'account/create.html', locals())
        else:
            new_group = models.Group()
            os.makedirs("E:\\upload\\group\\" + groupname)
            new_group.g_name = groupname
            new_group.email = user.email
            new_group.g_owner = user.name
            new_group.g_code = code()
            new_group.num = 1
            new_group.g_file_url = "E:\\upload\\group\\" + groupname
            new_group.save()
            user.group = new_group
            user.permission = True
            user.save()

            return redirect('/home/')
    return render(request, 'account/create.html', locals())


def joingroup(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    group_infos = models.Group.objects.all()
    if request.method == 'POST':
        message = "请检查填写的内容！"
        group_id = request.POST.get('group_id')
        code = request.POST.get('code')
        try:
            group = models.Group.objects.get(id=group_id)
        except:
            message = '组别不存在'
            return render(request, 'account/joingroup.html', locals())
        if code != group.g_code:
            message = '邀请码不正确'
            return render(request, 'account/joingroup.html', locals())
        else:
            if user.group != None:
                message = '您已经加入过另一用户组，请退出组后重试！'
                return render(request, 'account/joingroup.html', locals())
            member_name = request.session.get('user_name')
            user = models.User.objects.get(name=member_name)
            user.group = group
            user.permission = False
            user.save()
            old_number = group.number
            group.number = old_number + 1
            group.save()
            return redirect('/home/')

    return render(request, 'account/joingroup.html', locals())


def quit(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    user.group.number -= 1
    user.group.save()
    user.group = None
    user.permission = False
    user.save()
    return redirect('/home/')


def dismiss(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    group = models.Group.objects.get(g_owner=user_name)
    member_list = models.User.objects.filter(group=group)

    for member in member_list:
        if member.file != None:
            if member.file.f_group != 0:
                file_list = models.File.objects.filter(f_group=group.id)
                for f in file_list:
                    f.f_group = 0
                    f.save()

        member.group = None
        member.permission = False
        member.save()
    rootdir = "E:\\upload\\group\\" + group.g_name
    shutil.rmtree(rootdir, True)

    group.delete()
    return redirect('/home/')


def changegroupname(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user = models.User.objects.get(id=request.session.get('id'))
    if user.permission == True:
        if request.method == 'POST':
            groupname_form = forms.ChangegroupnameForm(request.POST)
            message = '请检查填写内容'
            if groupname_form.is_valid():  # 验证表单
                groupname = groupname_form.cleaned_data.get('newgroupname')
            if models.Group.objects.filter(g_name=groupname).exists():
                message = '该组名已存在'
                return render(request, 'account/changegroupname.html', locals())
            user.group.g_name = groupname
            user.group.save()
            return redirect('/home/')


"""
def get_md5(the_string):  # md5加密用户名作为用户密钥
        the_string_with_salt = the_string + the_salt
        the_md5 = hashlib.md5()
        the_md5.update(the_string_with_salt.encode('utf-8'))
        the_string_md5 = the_md5.hexdigest()
        return the_string_md5


def add_to_16(text):  # 扩充传送内容长度为16的倍数
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


def to_16(keys):  # 密钥扩充至16或24或32字符
    if len(keys.encode('utf-8')) <= 16:
        add = 16 - len(keys.encode('utf-8'))
        key = keys + ('\0' * add)
    elif len(keys.encode('utf-8')) <= 24:
        add = 24 - len(keys.encode('utf-8'))
        key = keys + ('\0' * add)
    elif len(keys.encode('utf-8')) <= 32:
        add = 32 - len(keys.encode('utf-8'))
        key = keys + ('\0' * add)
    else:
        key = keys[0:31]

    return key.encode('utf-8')


def encrypt(text, keys):  # AES加密过程
    key = keys.encode('utf-8')
    mode = AES.MODE_CBC
    iv = b'qqqqqqqqqqqqqqqq'
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)


def decrypt(text, keys):  # AES解密过程
    key = keys.encode('utf-8')
    mode = AES.MODE_ECB
    cryptor = AES.new(key, mode)
    plain_text = cryptor.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')


def encrypt_file(file_path, key):  # 加密文件函数
    f = open(file_path, 'r')
    plaintext = f.read()
    plaintext = plaintext.encode('utf-8')
    enc = encrypt(plaintext, key)
    f.close()
    f = open(file_path, 'w')
    f.write(str(enc))
    f.close()


def decrypt_file(file_path, key):  # 解密文件函数
    def pad(s):
        x = AES.block_size - len(s) % AES.block_size
        return s + ((str(bytes([x]))) * x)

    f = open(file_path, 'r')
    plaintext = f.read()
    x = AES.block_size - len(plaintext) % AES.block_size
    plaintext += ((bytes([x]))) * x
    dec = decrypt(plaintext, key)
    f.close()
    f = open(file_path, 'w')
    f.write(str(dec))
    f.close()


"""


@csrf_exempt
def upload_file(request):  # 文件上传upload
    if not request.session.get('is_login', None):
        return redirect('/login/')
    if request.method == 'GET':
        return render(request, 'account/upload.html')
    if request.method == 'POST':  # 请求方法为POST时，进行处理
        fname = request.POST.get("filename")
        fsize = int(request.POST.get("filesize"))
        file_encryped = request.POST.get("file")
        # 文件传输调用加密函数,解密以后命名为file
        file = Exchange.decrypt(file_encryped)

        file_owner_name = request.session.get('user_name')
        user = models.User.objects.get(name=file_owner_name)
        file_owner = user.name
        remain_space = user.remain_space
        cm = os.path.exists("E://upload//" + file_owner + "//" + fname + ".enc")
        if not cm:
            if fsize > remain_space:
                return HttpResponse("You don't have enough space left")
            file_info = File(f_name=fname, sort=re_match(fname), f_size=1 if 0 < fsize < 1024 else fsize / 1024,
                             f_owner=file_owner, f_key='',
                             f_url=os.path.join('E:\\upload', file_owner, fname), )
            file_info.save()
            destination = open(os.path.join("E:\\upload", file_owner, fname), 'wb+')  # 打开特定的文件进行二进制的写操作
            destination.seek(0)
            destination.write(file)
            destination.close()
            File_safestorage.encrypt_file(file_owner, fname)
            # 加密文件结束之后，利用RSA算法对密钥进行非对称一次加密，从数据库中提取一下密钥
            file=models.File.objects.get(Q(f_name=fname) & Q(f_owner=file_owner))
            print('look here')
            print(file.f_name)
            print(file.f_key)
            file_info.f_key = secret_key_rsa.encrypt_by_public_key(file.f_key)
            file_info.save()
            file = models.File.objects.get(Q(f_name=fname) & Q(f_owner=file_owner))
            print(file.f_key)

            # cmfile = models.File.objects.filter(Q(f_name=f.name) & Q(f_owner=file_owner))
            # if cmfile == None:

            user.remain_space = remain_space - fsize
            user.save()

            return redirect('/index/')

        else:
            form = UploadForm()  # A empty, unbound form
            return render(request, 'account/upload.html', {'form': form})


def re_match(filename):  # 匹配文件类型的正则
    regex_photo = re.compile(r'^.*\.(jpg|jpeg|png|gif|tif|bmp)$')
    regex_pdf = re.compile(r'^.*\.(pdf)$')
    regex_txt = re.compile(r'^.*\.(txt)$')

    if regex_photo.search(filename):
        return "photo"
    elif regex_pdf.search(filename):
        return "PDF"
    elif regex_txt.search(filename):
        return "TXT"
    else:
        return "others"


def photo(request):  # 图片类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(Q(sort="photo") & Q(f_owner=user_name))
    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/photo.html',
                  {'file_infos': file_infos, 'spaceprecent': spaceprecent, 'used': used, 'max': max,
                   'scaling': scaling})


def pdf(request):  # pdf类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(Q(sort="PDF") & Q(f_owner=user_name))
    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/pdf.html',
                  {'file_infos': file_infos, 'spaceprecent': spaceprecent, 'used': used, 'max': max,
                   'scaling': scaling})


def txt(request):  # txt类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(Q(sort="TXT") & Q(f_owner=user_name))
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/txt.html',
                  {'file_infos': file_infos, 'spaceprecent': spaceprecent, 'used': used, 'max': max,
                   'scaling': scaling})


def others(request):  # 其他类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(Q(sort="others") & Q(f_owner=user_name))
    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/others.html',
                  {'file_infos': file_infos, 'spaceprecent': spaceprecent, 'used': used, 'max': max,
                   'scaling': scaling})


'''def download(request, id):
    file_info = File.objects.get(id=id)
    print('下载的文件名：' + file_info.f_name)
    # 加密文件结束之前，利用RSA算法对密钥进行非对称一次解密，从数据库中提取一下密钥
    #secretkey_rsa_d(file_info.f_key)
    # !!调用解密
    File_safestorage.decrypt_file(file_info.f_name)
    file = open(file_info.f_url, 'rb')
    print(dir(file))
    print(file.read(8))  # 读取前字节，对其进行解密，解密过后写回原文件中，再进行下载
    response = FileResponse(file)
    response['Content-Disposition'] = 'attachment;filename="%s"' % urlquote(file_info.f_name)
    return response'''


@csrf_exempt
def download(request, id):  # 下载页面index/photo/pdf/others/txt/leadergroup/notleadergroup
    file_info = File.objects.get(id=id)
    owner = file_info.f_owner
    print('下载的文件名：' + file_info.f_name)
    print(file_info.f_key)
    file_info.f_key = secret_key_rsa.decrypt_by_private_key(file_info.f_key)
    print(file_info.f_key)
    file_info.save()
    file_info = File.objects.get(id=id)
    print(file_info.f_key)
    decrypted = File_safestorage.decrypt_file(owner, file_info.f_name + ".enc")
    file_info.f_key = secret_key_rsa.encrypt_by_public_key(file_info.f_key)
    print(file_info.f_key)
    file_info.save()
    encrypted = Exchange.encrypt(decrypted)

    # 传输加密函数，对decrypted进行加密,加密以后的字节流命名为encrypted
    # response = download_file(file_info)
    # print(response)
    return HttpResponse(json.dumps({"filename": file_info.f_name, "file": encrypted}),
                        content_type="application/json")  # 转成字节流


'''def download_file(file_info):
    file = open(file_info.f_url, 'rb')
    response = FileResponse(file)
    response['Content-Disposition'] = 'attachment;filename="%s"' % urlquote(file_info.f_name)
    return response'''


def delete(request, id):  # 删除文件
    if not request.session.get('is_login', None):
        return redirect('/login/')
    file_info = File.objects.get(id=id)
    file_info.f_url = file_info.f_url + '.enc'
    file_url = file_info.f_url
    size = file_info.f_size
    file_info.delete()

    file_owner_name = request.session.get('user_name')
    user = models.User.objects.get(name=file_owner_name)
    old_remain_space = user.remain_space
    user.remain_space = old_remain_space + size
    user.save()
    os.remove(file_url)
    return HttpResponseRedirect('/index/')


def leaderdelete(request, id):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    if user.permission == False:
        return redirect('/group/')
    file = File.objects.get(id=id)
    file.f_group = 0
    file.save()
    os.remove("E:\\upload\\group\\" + user.group.g_name + "\\" + file.f_name + ".enc")
    return HttpResponseRedirect('/group/')


def deletemember(request, id):  # 删除组员
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    if user.permission == False:
        return redirect('/group/')
    deleteuser = User.objects.get(id=id)
    if deleteuser.permission:
        return HttpResponseRedirect('/group/')
    deleteuser.group = None
    deleteuser.save()
    return HttpResponseRedirect('/group/')
