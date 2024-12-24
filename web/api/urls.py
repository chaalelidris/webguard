from django.conf.urls import include, url
from django.urls import path
from rest_framework import routers

from .views import *

app_name = 'api'
router = routers.DefaultRouter()
router.register(r'listTargets', ListTargetsDatatableViewSet)
router.register(r'notifications', InAppNotificationManagerViewSet, basename='notification')
router.register(r'hackerone-programs', HackerOneProgramViewSet, basename='hackerone_program')

urlpatterns = [
    url('^', include(router.urls)),
    path(
        'add/target/',
        AddTarget.as_view(),
        name='addTarget'),
   
    path(
        'queryInterestingSubdomains/',
        QueryInterestingSubdomains.as_view(),
        name='queryInterestingSubdomains'),
    
    
    path(
        'queryOsintUsers/',
        ListOsintUsers.as_view(),
        name='queryOsintUsers'),
    path(
        'queryMetadata/',
        ListMetadata.as_view(),
        name='queryMetadata'),
    
    
    
    path(
        'queryTargetsWithoutOrganization/',
        ListTargetsWithoutOrganization.as_view(),
        name='queryTargetsWithoutOrganization'),
    path(
        'queryTargetsInOrganization/',
        ListTargetsInOrganization.as_view(),
        name='queryTargetsInOrganization'),
    path(
        'listOrganizations/',
        ListOrganizations.as_view(),
        name='listOrganizations'),
    path(
        'listEngines/',
        ListEngines.as_view(),
        name='listEngines'),
    
    path(
        'listInterestingKeywords/',
        ListInterestingKeywords.as_view(),
        name='listInterestingKeywords'),
    path(
        'getFileContents/',
        GetFileContents.as_view(),
        name='getFileContents'),
    path(
        'vulnerability/report/',
        VulnerabilityReport.as_view(),
        name='vulnerability_report'),
    path(
        'tools/ip_to_domain/',
        IPToDomain.as_view(),
        name='ip_to_domain'),
    path(
        'tools/whois/',
        Whois.as_view(),
        name='whois'),
    path(
        'tools/reverse/whois/',
        ReverseWhois.as_view(),
        name='reverse_whois'),
    path(
        'tools/domain_ip_history',
        DomainIPHistory.as_view(),
        name='domain_ip_history'),
    path(
        'tools/cms_detector/',
        CMSDetector.as_view(),
        name='cms_detector'),
    path(
        'tools/cve_details/',
        CVEDetails.as_view(),
        name='cve_details'),
    path(
        'tools/waf_detector/',
        WafDetector.as_view(),
        name='waf_detector'), 
    path(
        'github/tool/get_latest_releases/',
        GithubToolCheckGetLatestRelease.as_view(),
        name='github_tool_latest_release'),
    path(
        'external/tool/get_current_release/',
        GetExternalToolCurrentVersion.as_view(),
        name='external_tool_get_current_release'),
    path(
        'tool/update/',
        UpdateTool.as_view(),
        name='update_tool'),
    path(
        'tool/uninstall/',
        UninstallTool.as_view(),
        name='uninstall_tool'),
	path(
        'tool/ollama/',
        OllamaManager.as_view(),
        name='ollama_manager'),
    path(
        'webguard/update/',
        WebguardUpdateCheck.as_view(),
        name='check_webguard_update'),
    
    path(
        'action/rows/delete/',
        DeleteMultipleRows.as_view(),
        name='delete_rows'),
    
    path(
        'search/history/',
        SearchHistoryView.as_view(),
        name='search_history'),
    # API for fetching currently ongoing scans and upcoming scans
    
    path(
        'action/create/project',
        CreateProjectApi.as_view(),
        name='create_project'),
    path(
        'toggle-bug-bounty-mode/', 
        ToggleBugBountyModeView.as_view(), 
        name='toggle_bug_bounty_mode'
    ),
]

urlpatterns += router.urls
