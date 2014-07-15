#!/usr/bin/python
# -*- coding: utf-8 -*-
from django.conf.urls import patterns, include, url
from django.conf.urls import *
from django.views.generic import RedirectView
# Uncomment the next two lines to enable the admin:
from django.contrib import admin 
# admin.autodiscover()
urlpatterns = patterns(('Iwork.views'),
     url(r'^login/', 'login', name='login' ),
     url(r'^logout/', 'logout', name='logout'),
     url(r'^admin/grouplist/', 'grouplist', name='grouplist'),
     url(r'^admin/serverlist/', 'serverlist', name='serverlist'),
     url(r'^admin/ipadd/', 'ipadd', name='ipadd'),
     url(r'^admin/groupadd/', 'groupadd', name='groupadd'),
     url(r'^admin/alone_command/', 'alone_command', name='alone_command'),
     url(r'^admin/file_transfer/', 'file_transfer', name='file_transfer'),
     url(r'^admin/file_upload/', 'upload_file', name='upload_file'),
     url(r'^admin/service_manager/', 'service_manager', name='service_manager'),
     url(r'^admin/service_add/', 'service_add', name='service_add'),
     url(r'^admin/deploy_env/', 'environment_list', name='environment_list'),
     url(r'^admin/deploy_env_add/', 'environment_add', name='environment_add'),
     url(r'^admin/envver_add/', 'envversion_add', name='envversion_add'),
     url(r'^admin/run_service/', 'run_service', name='run_service'),
     url(r'^admin/sshtypeadd/', 'ssh_protocoladd', name='ssh_protocoladd'),

     url(r'^admin/salt/', 'salt', name='salt'),
     url(r'^admin/salt_key_add/', 'salt_key_add', name='salt_key_add'),
)

