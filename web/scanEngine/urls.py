from django.contrib import admin
from django.urls import include, path

from . import views

urlpatterns = [
    path(
        '<slug:slug>/',
        views.index,
        name='scan_engine_index'),
    path(
        '<slug:slug>/add/',
        views.add_engine,
        name='add_engine'),
    path(
        '<slug:slug>/delete/<int:id>',
        views.delete_engine,
        name='delete_engine_url'),
    path(
        '<slug:slug>/update/<int:id>',
        views.update_engine,
        name='update_engine'),
    path(
        '<slug:slug>/tool_arsenal/update/<int:id>',
        views.modify_tool_in_arsenal,
        name='update_tool_in_arsenal'),
    path(
        '<slug:slug>/wordlist/',
        views.wordlist_list,
        name='wordlist_list'),
    path(
        '<slug:slug>/wordlist/add/',
        views.add_wordlist,
        name='add_wordlist'),
    path(
        '<slug:slug>/tool_arsenal/add/',
        views.add_tool,
        name='add_tool'),
    path(
        '<slug:slug>/wordlist/delete/<int:id>',
        views.delete_wordlist,
        name='delete_wordlist'),
    path(
        '<slug:slug>/interesting/lookup/',
        views.interesting_lookup,
        name='interesting_lookup'),
    path(
        '<slug:slug>/tool_settings',
        views.tool_specific_settings,
        name='tool_settings'),
    path(
        '<slug:slug>/api_vault',
        views.api_vault,
        name='api_vault'),
    path(
        '<slug:slug>/tool_arsenal',
        views.tool_arsenal_section,
        name='tool_arsenal'),
	path(
        '<slug:slug>/llm_toolkit',
        views.llm_toolkit_section,
        name='llm_toolkit'),
    path(
        '<slug:slug>/webguard_settings',
        views.webguard_settings,
        name='webguard_settings'),
    path(
        '<slug:slug>/notification_settings',
        views.notification_settings,
        name='notification_settings'),
    path(
        '<slug:slug>/proxy_settings',
        views.proxy_settings,
        name='proxy_settings'),
    path(
        '<slug:slug>/hackerone_settings',
        views.hackerone_settings,
        name='hackerone_settings'),
    path(
        '<slug:slug>/report_settings',
        views.report_settings,
        name='report_settings'),
    path(
        '<slug:slug>/testHackerone/',
        views.test_hackerone,
        name='testHackerone'
    ),
]
