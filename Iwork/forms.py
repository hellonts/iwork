#coding=utf-8
from django import forms
from django.contrib.auth.models import User
from .models import Group, Ip, System_servermanager, Envname_ver, Deployment_Environment, Ssh_protocol
class LoginForm(forms.Form):
    username = forms.CharField(
        required=True,
        label=u"用户名:",
        error_messages={'required': '请输入用户名'},
        widget=forms.TextInput(
            attrs={
                'placeholder':u"用户名",
		'class':'form-control',
            }
        ),
    )
    password = forms.CharField(
        required=True,
        label=u"密   码:",
        error_messages={'required': u'请输入密码'},
        widget=forms.PasswordInput(
            attrs={
                'placeholder':u"密码",
		'class':'form-control',
            }
        ),
    )
    def clean(self):
        if not self.is_valid():
            raise forms.ValidationError(u"用户名和密码为必填项")
        else:
            cleaned_data = super(LoginForm, self).clean()
			
class IpForm(forms.Form):
    data = (Ssh_protocol.objects.all())
    ip_address = forms.IPAddressField(required=True,label='主机IP:',error_messages={'required': '请输入ip地址','invalid': u'请输入正确的ip'},max_length=20,widget=forms.TextInput(attrs={'class':'form-control'}),)
    port = forms.IntegerField(required=True,label='端口:',widget=forms.TextInput(attrs={'class':'form-control'}),)
    user = forms.CharField(required=True,max_length=50,label='用户名:',widget=forms.TextInput(attrs={'class':'form-control'}),)
    passwd = forms.CharField(required=True,max_length=100,label='密码:',widget=forms.PasswordInput(attrs={'class':'form-control'}),)
    protocol_type = forms.ModelChoiceField(queryset=Ssh_protocol.objects.all(),required=True,error_messages={'required': '请选择一项'},label='协议:',widget=forms.Select(attrs={'class':'form-control'}),)
    
    hostname = forms.CharField(max_length=50,required=True,label='主机名称:',widget=forms.TextInput(attrs={'class':'form-control'}),)

class GroupForm(forms.Form):
    group_name = forms.CharField(required=True,label='组名:',max_length=20,error_messages={'required': '请输入组名'},widget=forms.TextInput(attrs={'class':'form-control'}),)

class Ssh_protocolForm(forms.Form):
    ssh_protocol_type = forms.CharField(required=True,label='连接类型:',max_length=10,error_messages={'required': ':请输入连接类型'},widget=forms.TextInput(attrs={'class':'form-control'}),)

class DocumentForm(forms.Form):
    docfile = forms.FileField(required=True,label='请选择文件',error_messages={'required': '请选择文件'},help_text='max. 45 megabytes',widget=forms.FileInput(attrs={'class':'multifile','id':'docfile'}),)

class ServeraddForm(forms.Form):
    servername = forms.CharField(max_length=20)
    scriptname = forms.CharField(max_length=20)
   
class EnviromentForm(forms.Form):
    envname = forms.CharField(required=True,label='请输入部署环境名称:',widget = forms.TextInput(attrs={"class":"form-control"}),error_messages={'required': '不能为空'},)
    scriptname = forms.CharField(required=True,label='请输入要上传脚本的名称:',widget = forms.TextInput(attrs={"class":"form-control"}),error_messages={'required': '不能为空'},)
    scriptpath = forms.CharField(initial=u'/root/svnchina/iwork/Iwork/templates/media/documents/',required=True,label='请输入要上传脚本的名称路径:',widget = forms.TextInput(attrs={"class":"form-control"}),error_messages={'required': '不能为空'},)
    env_ver = forms.ModelChoiceField(queryset=Envname_ver.objects.all(),required=True,error_messages={'required': '请选择一项'},label='请选择部署环境的版本号:',widget = forms.Select(attrs={'class':'form-control'}))
class Envversion_addForm(forms.Form):
    envver = forms.FloatField(required=True,label='请输入要添加的版本号:',error_messages={'required': '不能为空'},widget=forms.TextInput(attrs={"class":"form-control"}))
