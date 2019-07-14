from django.shortcuts import render,redirect
from .models import *
from django.http import HttpResponse
from django.contrib import auth
from django.contrib.auth import hashers #用户密码加密
from django.db import utils


def register(request):
    # 如果是GET请求返回register页面
    if request.method == 'GET':
        return render(request,'users/register.html')
    else:
    # 如果是POST请求处理登录业务逻辑
    #获取所有的提交内容
        username = request.POST.get('uname','')
        password = request.POST.get('upwd','')
        password2 = request.POST.get('upwdconfirm','')
        email = request.POST.get('email','')
        phone = request.POST.get('phone','')
        #做验证判断
        #验证用户是否注册过
        olduser = User.objects.filter(username=username)
        if olduser:
            return HttpResponse('该用户已存在!')
        #验证两次密码是否一致
        if password != password2:
            return HttpResponse('两次密码不一致')
        #判断是否有未填写信息
        if not (username and password and email and phone):
            return HttpResponse('输入内容不能为空')

        #注册用户业务
        #密码加密
        password_sha1 = hashers.make_password(password,None,'pbkdf2_sha1')
        #将用户提交的数据保存到数据库完成注册
        try:
            User.objects.create(username=username,nickname=username,password=password_sha1,phone=phone,email=email)
            print('注册用户：',username,'成功')
        #导入数据库报错的对象
        # from django.db import utils
        except utils.DatabaseError as e:
            print('用户注册失败','原因：',e)
            return HttpResponse('注册失败 数据库报错')
        return HttpResponse('注册成功 <a href="/">返回首页</a>')

def login(request):
    if request.method == 'GET':
        return render(request,'users/login.html')
    else:
        # 如果是post请求
        # 验证验证码是否正确
        # 查看用户输入的验证码和session中的验证码是否一致
        # 验证码判断不区分大小写
        user_verify = request.POST.get('verify').lower()
        verify_code = request.session['verifycode'].lower()
        if user_verify != verify_code:
        # 不一致时返回响应对象
        # 验证码错误
            return HttpResponse('验证码错误')
        # 验证用户名和密码是否为空
        # 为空时返回响应对象
        # 用户名或密码不能为空
        username = request.POST.get('username','')
        password = request.POST.get('password','')
        if not username or not password:
            return HttpResponse('用户名或密码不能为空')
        # 验证用户名和密码是否正确
        # from django.contrib import auth
        #验证用户名和密码是否通过 如果通过会返回此User对象
        user = auth.authenticate(request=request,username=username,password=password)
        if user and user.is_active:
            #通过验证
            #通过login将user和request对象关联
            # 此后可以通过request.user的方式访问用户
            auth.login(request,user)
            print('user:'+user.username+'is login!')
            #返回首页
            # return HttpResponse('登录成功'
            return redirect('/')
        else:
            return HttpResponse('登录失败')

def logout(request):
    # 如果通过get请求访问
    if request.method == 'GET':
    # 执行auth中的logout函数
    # 将user和Request对象解绑
        auth.logout(request)
        return redirect('/')

def modpwd(request):
    # 如果是GET请求
    # 响应页面
    # personal_password.html
    if request.method == 'GET':
        return render(request,'users/personal_password.html')
    # 如果是POST请求
    else:
#     实现修改密码业务
#     获取用户提交原密码的值
        upwd = request.POST.get('upwd','')
#     获取用户提交新密码的值
        npwd = request.POST.get('npwd','')
#     获取用户提交重复新密码的值
        rpwd = request.POST.get('rpwd','')
#     获取用户对象
        user = request.user
        #if upwd == user.password
#     到数据库中验证密码
#     通过user对象的check_password()
#     判断密码是否正确
        if user.check_password(upwd):
            # 验证新密码是否为空
            if not npwd:
                return HttpResponse('新密码不能为空')
#     验证两新密码是否一致
            if npwd != rpwd:
                return HttpResponse('两次密码不一致')
            #如果验证都通过
            #调用user对象set_password()函数
            #将新密码作为参数传入
            user.set_password(npwd)
            #保存user对象
            user.save()
            #返回首页
            return redirect('/')

        #如果旧密码未通过返回密码错误
        else:
            return HttpResponse('密码错误')

