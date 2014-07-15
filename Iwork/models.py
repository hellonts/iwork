#coding=utf-8
from django.db import models

# Create your models here.

# create protocol_type
class Ssh_protocol(models.Model):
    ssh_protocol_type = models.CharField(max_length=10)
    def __unicode__(self):
        return self.ssh_protocol_type

# create Ip
class Ip(models.Model):
    ip_address = models.IPAddressField(max_length=20,unique=True)
    port = models.CharField(max_length=10)
    user = models.CharField(max_length=30)
    passwd = models.CharField(max_length=50)
    protocol_type = models.ForeignKey(Ssh_protocol)
    hostname = models.CharField(max_length=50,blank=True)
    publish_time = models.DateTimeField(auto_now_add=True)
    def __unicode__(self):
        return self.ip_address

   
# create grouplist
class Group(models.Model):
    group_name = models.CharField(max_length=20,blank=True)
    ips = models.ManyToManyField(Ip,blank=True)
    publish_time = models.DateTimeField(auto_now_add=True)
    
    iplist = []
    def save(self, *args, **kwargs):
	super(Group, self).save()
	for i in self.iplist:
	    p, created = Ip.objects.get_or_create(ip_address=i)
	    self.ips.add(p)

    def __unicode__(self):
        return u'%s %s' % (self.group_name, self.publish_time)

# create system_resource
class System_resource(models.Model):
    system_ver = models.CharField(max_length=50,blank=True)
    digit_number = models.CharField(max_length=10,blank=True)
    cpu = models.CharField(max_length=50,blank=True)
    cpu_number = models.CharField(max_length=50,blank=True)
    physics_mem = models.CharField(max_length=50,blank=True)
    swap_mem = models.CharField(max_length=50,blank=True)
    disk = models.CharField(max_length=50,blank=True)
    network_card = models.CharField(max_length=50,blank=True)
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
        return self.system_ver

# create System_command
class System_command(models.Model):
    text = models.TextField(max_length=200,blank=True)
    input_time = models.DateTimeField(auto_now_add=True)
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
	return self.text

# create System_stat
class System_stat(models.Model):
    user_stat = models.CharField(max_length=200,blank=True)
    time = models.DateTimeField(auto_now_add=True)
    server_stat =  models.CharField(max_length=200,blank=True)
    system_resource =  models.ForeignKey(System_resource) 
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
        return self.user_stat

# create System_task
class System_task(models.Model):
    file_name = models.CharField(max_length=50,blank=True)
    time = models.DateTimeField(auto_now_add=True)
    path = models.FilePathField(max_length=50,blank=True)
    comm = models.CharField(max_length=50,blank=True)
    processing_time = models.DateTimeField(auto_now_add=True)
    back_state = models.CharField(max_length=50,blank=True)
    ip = models.ForeignKey(Ip)
#   send_mail = 
    def __unicode__(self):
        return self.file_name




# create Server
#class Server(models.Model):
#    http = 
#    mysql =
#    cache =
#    ip = 

# create Network
class Network(models.Model):
    input = models.CharField(max_length=50,blank=True)
    time = models.DateTimeField(auto_now_add=True)
    output = models.CharField(max_length=50,blank=True)
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
        return self.input

# create Syslog
class Syslog(models.Model):
    system_log = models.TextField(max_length=300,blank=True)
    time = models.DateTimeField(auto_now_add=True) 
    server_log = models.TextField(max_length=300,blank=True)
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
        return self.system_log

# create System_use
class System_use(models.Model):
    mem = models.CharField(max_length=50,blank=True)
    time = models.DateTimeField(auto_now_add=True)
    cpu = models.CharField(max_length=50,blank=True)
    swap = models.CharField(max_length=50,blank=True)
    disk = models.CharField(max_length=50,blank=True)
    system_load = models.CharField(max_length=50,blank=True)
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
        return self.mem

# create System_monitoring
class System_monitoring(models.Model):
    online_user = models.CharField(max_length=50,blank=True)
    time = models.DateTimeField(auto_now_add=True)
#    server = models.ForeignKey(Server)
    networK = models.ForeignKey(Network)
    syslog = models.ForeignKey(Syslog)
    system_use = models.ForeignKey(System_use)
    ip = models.ForeignKey(Ip)
    def __unicode__(self):
        return self.online_user

# create upload_file
class Document(models.Model):
     docfile = models.FileField(upload_to='documents/%Y-%m-%d')

# create System_servermanager
class System_servermanager(models.Model):
    servername = models.CharField(max_length=20,blank=True)
    scriptname = models.CharField(max_length=20,blank=True)
    time = models.DateTimeField(auto_now_add=True)
    def __unicode__(self):
        return self.servername

# create envname_ver
class Envname_ver(models.Model):
    envver = models.FloatField(blank=True, null=True)
    time = models.DateTimeField(auto_now_add=True)
    def __unicode__(self):
        return unicode(self.envver)

# create Deployment_environment
class Deployment_Environment(models.Model):
    envname = models.CharField(max_length=20)
    scriptname = models.CharField(max_length=20)
    scriptpath = models.CharField(max_length=255)
    env_ver = models.ForeignKey(Envname_ver)
    def __unicode__(self):
	return '%s %s %s ' % (self.envname,self.scriptname,self.env_ver)



