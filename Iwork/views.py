# Create your views here.
#coding=utf-8
from django.shortcuts import render_to_response, render, get_object_or_404
from Iwork.models import Group, System_resource, Ip, Ssh_protocol, Document, System_servermanager, Deployment_Environment, Envname_ver
from django.http import Http404, HttpResponseRedirect, HttpResponse
from django.template import RequestContext

from Iwork.forms import LoginForm, IpForm, GroupForm, Ssh_protocolForm, DocumentForm, ServeraddForm, EnviromentForm, Envversion_addForm
from django.forms.formsets import formset_factory

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import auth
from django.contrib import messages
from .forms import LoginForm
from .forms import LoginForm
import json, os, time, sys
from datetime import datetime
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger, InvalidPage
#from filelocation import handle_uploaded_file


# admin_login
def login(request):
    if request.method == 'GET':
        form = LoginForm()
        return render_to_response('login.html', RequestContext(request, {'form': form,}))
    else:
        form = LoginForm(request.POST)
        if form.is_valid():
            username = request.POST.get('username', '')
            password = request.POST.get('password', '')
            user = auth.authenticate(username=username, password=password)
            if user is not None and user.is_active:
                auth.login(request, user)
#		return HttpResponseRedirect('/Iwork/admin')
                return render_to_response('admin_bglist.html', RequestContext(request, {'form': form,'user_is_none':True}))
	        return HttpResponseRedirect('/Iwork/admin')		
	    else:
                return render_to_response('login.html', RequestContext(request, {'form': form,'password_is_wrong':True}))
#            return HttpResponseRedirect('/Iwork/admin')
        elif not form.is_valid():
	    return render_to_response('login.html', RequestContext(request, {'form': form,'user_is_none':True}))
        else:
            return render_to_response('login.html', RequestContext(request, {'form': form,}))


@login_required 
def logout(request):  
    auth.logout(request)  
    return HttpResponseRedirect("login/") 

@login_required 
def grouplist(request):
    groups = Group.objects.all()
    paginator = Paginator(groups,6)
    page = request.GET.get('page')
    try:
        pages = paginator.page(page)
    except PageNotAnInteger:
        pages = paginator.page(1)
    except (EmptyPage,InvalidPage):
        pages = paginator.page(paginator.num_pages)
	 
    return render_to_response("admin_group_list.html", RequestContext(request,{"pages": pages}))

@login_required
def serverlist(request):
    servers = Ip.objects.all()
    paginator = Paginator(servers,6)
    page = request.GET.get('page')
    try:
	pages = paginator.page(page)
    except PageNotAnInteger:
	pages = paginator.page(1)
    except (EmptyPage,InvalidPage):
	pages = paginator.page(paginator.num_pages)
    if request.method =='POST':
	if request.POST.has_key('delete'):
	    iplist = request.POST.getlist('answer',None)
	    for i in iplist:
                de = Ip.objects.get(id=i)
                de.delete()

        return render_to_response("admin_server_list.html", RequestContext(request,locals()))
    else:
	 return render_to_response("admin_server_list.html", RequestContext(request,locals()))

@login_required
def ipadd(request):
    username = request.session.get('username','')
    grouplist = Group.objects.all()
    protocol_type = Ssh_protocol.objects.all()
    if request.method == "POST":
        form = IpForm(request.POST)
        if form.is_valid():
	    cd = form.cleaned_data
	    ID = request.POST.get('protocol_type')
	    protocol = Ssh_protocol.objects.get(id=ID)
            ip_address = cd['ip_address'].strip()
            port = cd['port']
            user = cd['user'].strip()
            passwd = cd['passwd'].strip()
            hostname = cd['hostname'].strip()  
	    ip = Ip(ip_address=ip_address, port=port, user=user, passwd=passwd, protocol_type=protocol, hostname=hostname)
	    ip.save()
            return HttpResponseRedirect('/Iwork/admin/serverlist/')
	else:
	    return render_to_response('admin_ip_add.html',context_instance=RequestContext(request,locals()))

    else:
        form = IpForm()
    return render_to_response("admin_ip_add.html",context_instance=RequestContext(request,locals()))      
@login_required
def groupadd(request):
    if request.method == "POST":
        form = GroupForm(request.POST)
	ip = IpForm(request.POST)
	ips = Ip.objects.all()
	if form.is_valid() :
	    cd = form.cleaned_data
	    name = cd['group_name'].strip()
	    group = Group(group_name=name) 
	    group.save()
	    
  	    try:
	        iplists = request.POST.getlist('answer',None)
	        for iplist in iplists:
		    group.ips.add(Ip.objects.get(ip_address=iplist))
		    group.save()
	    except Group.DoesNotExist:
	        raise Http404

##	    for iplist in Ips:
#		group.ips.add(Ip.objects.get(ip_address = iplist))
##		p,created = Ip.objects.get_or_create(ip_address=iplist)
##		group.ips.add(p)
#	    for splitIp in splitIps:
#   		p = Ip(id = int(splitIp.id))
#	        group.ips.add(p)
#		group.save()
	    return  HttpResponseRedirect('/Iwork/admin/grouplist')
	
    else:
	form = GroupForm()
        ip = IpForm()	
        ips = Ip.objects.all()
    return render_to_response('admin_group_add.html',context_instance=RequestContext(request,{"form": form,"ip":ip,"ips":ips}))


@login_required
def ssh_protocoladd(request):
    if request.method == "POST":
        ssh_protocol = Ssh_protocolForm(request.POST)
	if ssh_protocol.is_valid():
	    cd = ssh_protocol.cleaned_data
	    ssh_protocol_type = cd['ssh_protocol_type']
	    ssh_protocol_s = Ssh_protocol(ssh_protocol_type=ssh_protocol_type,)
	    ssh_protocol_s.save()
	    return HttpResponseRedirect('/Iwork/admin/ipadd/')
	else:
	    return render_to_response('admin_sshtype_add.html', context_instance=RequestContext(request,locals()))


    else:
        ssh_protocol = Ssh_protocolForm()
	
        return render_to_response('admin_sshtype_add.html',{'ssh_protocol': ssh_protocol,}, context_instance=RequestContext(request))

@login_required
def alone_command(request):
    import paramiko
    iplist = Ip.objects.all()
    ssh_protocol_p = Ssh_protocol.objects.all()
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if request.method == "POST":
	if request.POST.has_key('connect'):
            ID = request.POST.get('select')
	    ip = Ip.objects.get(id=ID).ip_address
	    Port = Ip.objects.get(id=ID).port
	    User = Ip.objects.get(id=ID).user
	    Passwd = Ip.objects.get(id=ID).passwd
	    ssh_protocol_p = Ssh_protocol.objects.get(id=1)
	    hostname = Ip.objects.get(id=ID).hostname
	    if ssh_protocol_p == "ssh2":
	        ssh.connect(ip,int(Port),User,Passwd,timeout=3)
	    else:
		pass
	elif request.POST.has_key('break'):
	    ssh.close()
        elif request.POST.has_key('zhixing'):
	    try:
		ID = request.POST.get('select',None)
                ip = Ip.objects.get(id=ID).ip_address
                Port = Ip.objects.get(id=ID).port
                User = Ip.objects.get(id=ID).user
                Passwd = Ip.objects.get(id=ID).passwd
	        hostname = Ip.objects.get(id=ID).hostname
		ssh.connect(ip,int(Port),User,Passwd,timeout=3)
                Command = request.POST.get('command')
	    except Ip.DoesNotExist:
                raise Http404
#	if request.POST.has_key('zhixing'):
#	    Command = request.POST.get('command')
#	    p = Popen(Command,shell=True,stdout=PIPE,stderr=PIPE)
#	    stdout,stderr = p.communicate()
#	    display =stdout.splitlines()
#	    disdata = []
#	    for line in display:
#	        disdata.append(line)
		
	    
	    stdin, stdout, stderr = ssh.exec_command(Command,timeout=3,get_pty=True)
  	    disdata = stdout.readlines()
#	    disdata = []
#	    for line in display:
#	        disdata.append(line)
	
	return render_to_response('admin_alone_c.html',locals(), context_instance=RequestContext(request))
    
    return render_to_response('admin_alone_c.html',locals(), context_instance=RequestContext(request))

@login_required
def file_transfer(request):
    import paramiko
    iplist = Ip.objects.all()
    if request.method == "POST":
        if request.POST.has_key('put'):
	    messages.success(request, '执行成功')  
            ID = request.POST.get('select')
            ip = Ip.objects.get(id=ID).ip_address
            Port = Ip.objects.get(id=ID).port
            User = Ip.objects.get(id=ID).user
            Passwd = Ip.objects.get(id=ID).passwd
	    f = paramiko.Transport((str(ip),int(Port)))
	    f.connect(username=str(User),password=str(Passwd))
	    sftp = paramiko.SFTPClient.from_transport(f)
	    remotepath = request.POST.get('remotepath')
	    localpath = request.POST.get('localpath')
	    sftp.put(localpath,remotepath)
	    f.close()
	elif request.POST.has_key('get'):
	    messages.success(request, '执行成功')  
	    ID = request.POST.get('select')
            ip = Ip.objects.get(id=ID).ip_address
            Port = Ip.objects.get(id=ID).port
            User = Ip.objects.get(id=ID).user
            Passwd = Ip.objects.get(id=ID).passwd
            f = paramiko.Transport((str(ip),int(Port)))
            f.connect(username=str(User),password=str(Passwd))
            sftp = paramiko.SFTPClient.from_transport(f)
            remotepath = request.POST.get('remotepath')
            localpath = request.POST.get('localpath')
            sftp.get(remotepath,localpath)
            f.close()
	    return render_to_response('admin_file_t.html',locals(), context_instance=RequestContext(request))

    return render_to_response('admin_file_t.html',locals(), context_instance=RequestContext(request))
#@login_required
#def batch_processing(request):
#@login_required
#def service_manager(request):备份
#    serverlist = System_servermanager.objects.all()
#    paginator = Paginator(serverlist,6)
#    page = request.GET.get('page')
#    try:
#        pages = paginator.page(page)
#    except PageNotAnInteger:
#        pages = paginator.page(1)
#    except (EmptyPage,InvalidPage):
#        pages = paginator.page(paginator.num_pages)
#
#    return render_to_response("admin_service_manage.html", RequestContext(request,{"pages": pages}))

@login_required
def service_manager(request):
    import paramiko, pickle, re
    path = os.path.realpath(os.path.dirname(__file__))
    id = 'id_data'
    service = 'service_data'
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    reload(sys)
    sys.setdefaultencoding('utf-8')
    times = time.time()	
    iplist = Ip.objects.all()
    if request.method == 'POST':
	if request.POST.has_key('yes') or request.POST.has_key('change'):
	    if request.POST.has_key('yes'):
		pass
	    elif request.POST.has_key('change'):
		Oldip = request.POST.get('oldip')
		oldid = Ip.objects.get(ip_address=Oldip).id
		Oldid = str(oldid)
		Port = Ip.objects.get(id=Oldid).port
		User = Ip.objects.get(id=Oldid).user
		Passwd = Ip.objects.get(id=Oldid).passwd	

	
		Old_name = request.POST.get('servicename')
#		Old_Name = re.findall(r'\w+',Old_name)
		Old_Name = re.match(r'\w*..*\w[^|onoff启用关闭]',Old_name)
#		newname = Old_Name.pop()
		newname = Old_Name.group()
		servicelen = len(newname)
#		Oldnamelen = len(Old_name)
		newlen = servicelen + 1
		status_n = Old_name[newlen:]
		if status_n == '关闭' or status_n == 'off':
		    newstatus = 'on'
		else:
		    newstatus = 'off'
		ssh.connect(Oldip,int(Port),User,Passwd,timeout=3)
	        change = "chkconfig %s %s" %(newname,newstatus)	
	        stdin, stdout_change, stderr = ssh.exec_command(change,timeout=3,get_pty=True)

	    ssh_protocol_p = Ssh_protocol.objects.all()
	    ID = request.POST.get('select')
	    if ID == None:
                ID = Oldid
            else:
                ID = ID
	    IDS = Ip.objects.get(id=ID).ip_address
	    f = open('%s/%s' %(path,id),'wb')
	    pickle.dump(IDS,f)
	    f.close()
            ip = Ip.objects.get(id=ID).ip_address
            Port = Ip.objects.get(id=ID).port
            User = Ip.objects.get(id=ID).user
            Passwd = Ip.objects.get(id=ID).passwd	
	    ssh.connect(ip,int(Port),User,Passwd,timeout=3)
	    name = "chkconfig --list | awk '{print $1}'"
	    status = "chkconfig --list | awk '{print $5}'| cut -c 3-5"
	    stdin, stdout_name, stderr = ssh.exec_command(name,timeout=3,get_pty=True)
	    stdin, stdout_status, stderr = ssh.exec_command(status,timeout=3,get_pty=True)
	    Name = stdout_name.readlines()
	    Status = stdout_status.readlines()
	    items=[]
	    for i,value in enumerate(Name): 
	        list = {}
	        list['name'] = Name[i]
	        list['status'] = Status[i]
	        items.append(list)
	    f = open('%s/%s' %(path,service),'wb')
	    pickle.dump(items,f)
	    paginator = Paginator(items,6)
            page = request.GET.get('page')
            try:
                pages = paginator.page(page)
            except PageNotAnInteger:
                pages = paginator.page(1)
            except (EmptyPage,InvalidPage):
                pages = paginator.page(paginator.num_pages)

	    ssh.close()
	    f.close()
	

	
	



	return render_to_response("admin_service_manage.html", RequestContext(request,locals()))
    else:
	path = os.path.realpath(os.path.dirname(__file__))
	idfile = os.path.exists('%s/%s' %(path,id))
	if idfile == False:
	    os.system('%s %s/%s' % ('touch',path,id))
	else:
	    id = open('%s/%s' %(path,id),'rb')
 	    IDS = pickle.load(id)
	servicefile = os.path.exists('%s/%s' %(path,service))
	if servicefile == False:
	    os.system('%s %s/%s' %('touch',path,service))
	else:
	    f = open('%s/%s' %(path,service),'rb')
            items = pickle.load(f)
            paginator = Paginator(items,6)
            page = request.GET.get('page')
            try:
                pages = paginator.page(page)
            except PageNotAnInteger:
                pages = paginator.page(1)
            except (EmptyPage,InvalidPage):
                pages = paginator.page(paginator.num_pages)    
	    f.close()	
	    id.close()
        return render_to_response("admin_service_manage.html", RequestContext(request,locals())) 	
		


def service_add(request):
    serverlist = System_servermanager.objects.all()	
    if request.method == 'POST':
	form = ServeraddForm(request.POST)
        fileform = DocumentForm(request.POST, request.FILES)
	if form.is_valid() and fileform.is_valid():
	    cd = form.cleaned_data
	    servername = request.POST.get('servername')
	    servername = cd['servername'].strip()   
	    scriptname = request.POST.get('scriptname')
	    scriptname = cd['scriptname'].strip()
	    server_manager_list = System_servermanager(servername=servername,scriptname=scriptname)
	    server_manager_list.save()

	    f = Document(docfile = request.FILES['docfile'])
	    f.save()		
            return HttpResponseRedirect('/Iwork/admin/service_manager/')
    else:
	form = ServeraddForm()
	fileform = DocumentForm()
    return render_to_response('admin_service_add.html',locals(),context_instance=RequestContext(request))

def run_service(request):
    from subprocess import Popen, PIPE
    serverlist = System_servermanager.objects.all()
    iplist = Ip.objects.all()
    if request.method == 'POST':
	if request.POST.has_key('run'):
	    ID = request.POST.get('select')
	    ip = Ip.objects.get(id=ID).ip_address
	    User = Ip.objects.get(id=ID).user 
   	    Passwd = Ip.objects.get(id=ID).passwd 
   	    parameter = request.POST.get('parameter')
#	    IDserver = request.POST.get('server_manager')
	    script_path = request.POST.get('script_path') 
#	    script_name = server_manager.object.get(id=IDserver).scriptname
	    cmd = "%s -p %s ssh %s@%s sh %s" % ('sshpass',Passwd,User,ip,script_path)
	    p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
	    out, err = p.communicate()
	    commandout = out.splitlines()
	    return render_to_response('admin_service_run.html',locals(), context_instance=RequestContext(request))
	
    return render_to_response('admin_service_run.html',locals(), context_instance=RequestContext(request))	    
    

@login_required
def upload_file(request):
    files = Document.objects.all()
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
	if form.is_valid():
	    messages.success(request, '上传成功')
	    file = request.FILES.getlist('docfile')
	    for fi in file:
	    	f = Document(docfile = fi)
		f.save()
	    return HttpResponseRedirect('/Iwork/admin/file_upload/')
	else:
	    return render_to_response('admin_file_up.html',RequestContext(request, locals()))
    else:
        form = DocumentForm()
    return render_to_response('admin_file_up.html',RequestContext(request, locals()))


@login_required
def environment_list(request):
    Environment_list = Deployment_Environment.objects.all()
    paginator = Paginator(Environment_list,6)
    page = request.GET.get('page')
    try:
        pages = paginator.page(page)
    except PageNotAnInteger:
        pages = paginator.page(1)
    except (EmptyPage,InvalidPage):
        pages = paginator.page(paginator.num_pages)

    return render_to_response("admin_deploy_env.html", RequestContext(request,{"pages": pages}))

@login_required
def environment_add(request):
    path = os.path.realpath(os.path.dirname(__file__))
    date = datetime.now()
    year = date.year
    month = date.month
    day = date.day
    Date = '%d-%d-%d'% (year,month,day)
    fullpath = '%s/templates/media/documents/%s/' %(path,Date) 
    vers = Envname_ver.objects.all()
    if request.method == 'POST':
        form = EnviromentForm(request.POST)
	if form.is_valid():
	    cd = form.cleaned_data
	    name = cd['envname']
	    script_name = cd['scriptname']
	    Script_path = '%s%s'% (fullpath,script_name)
	    ID = request.POST.get('env_ver')
	    ver = Envname_ver.objects.get(id=ID)
	    env = Deployment_Environment(envname=name, scriptname=script_name, scriptpath=Script_path, env_ver=ver)
	    env.save()
#	    file = request.FILES.getlist('docfile')
#            for fi in file:
#                f = Document(docfile = fi)
#                f.save()
	    return HttpResponseRedirect('/Iwork/admin/deploy_env/') 
	else:
	    pass
    else:
	form = EnviromentForm()
    return render_to_response('admin_environment_add.html',RequestContext(request, locals())) 



#添加部署版本
@login_required
def envversion_add(request):
    if request.method == 'POST':
	form = Envversion_addForm(request.POST)
	if form.is_valid():
	    messages.success(request, '添加成功')
	    cd = form.cleaned_data
	    ver = cd['envver']	    
	    envadd = Envname_ver(envver=ver)
	    envadd.save()
       	    return HttpResponseRedirect('/Iwork/admin/deploy_env_add/')
    else:
	form = Envversion_addForm()
    return render_to_response('admin_envver_add.html',RequestContext(request, locals()))

# saltstack_salt
@login_required
def salt(request):
    from subprocess import Popen, PIPE
    if request.method =='POST':
	if request.POST.has_key('salt_key_list'):
            cmd="salt-key -l acc --out=txt"
	    p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
	    out, err = p.communicate()
	    data = out.splitlines()
	elif request.POST.has_key('salt_key_add'):
	    keyadd='keyadd'
	    	    






        return render_to_response('admin_salt.html',RequestContext(request, locals()))

    else:
        return render_to_response('admin_salt.html',RequestContext(request, locals()))

# salt_key_add
@login_required
def salt_key_add(request):
    if request.method == 'POST':
	if request.POST.has_key('add'):
	   a='123' 

 	return render_to_response('admin_salt_keyadd.html',RequestContext(request, locals()))

    else:
	return render_to_response('admin_salt_keyadd.html',RequestContext(request, locals()))

