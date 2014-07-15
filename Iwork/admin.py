#!/usr/bin/python
# -*- coding: utf-8 -*-

from django.contrib import admin
from Iwork.models import Group, Ip, Ssh_protocol 

class GroupAdmin(admin.ModelAdmin):
    list_display = ('group_name','publish_time')
    filter_horizontal = ('ips',)

class IpAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'port','user', 'passwd', 'protocol_type','hostname')
    list_filter = ('publish_time',)
class Ssh_protocolAdmin(admin.ModelAdmin):
    list_display = ('id', 'ssh_protocol_type')
	
admin.site.register(Group, GroupAdmin)
admin.site.register(Ssh_protocol, Ssh_protocolAdmin)
admin.site.register(Ip,IpAdmin)
