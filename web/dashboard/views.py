import json
import logging

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib import messages
from django.db.models import Count
from django.db.models.functions import TruncDay
from django.dispatch import receiver
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from rolepermissions.roles import assign_role, clear_roles
from rolepermissions.decorators import has_permission_decorator
from django.template.defaultfilters import slugify

from targetApp.models import Domain
from dashboard.models import *
from webGuard.definitions import *


logger = logging.getLogger(__name__)

def index(request, slug):
    try:
        project = Project.objects.get(slug=slug)
    except Exception as e:
        # if project not found redirect to 404
        return HttpResponseRedirect(reverse('four_oh_four'))

    domains = Domain.objects.filter(project=project)

    domain_count = domains.count()

    last_7_dates = [(timezone.now() - timedelta(days=i)).date()
                    for i in range(0, 7)]

    context = {
        'dashboard_data_active': 'active',
        'domain_count': domain_count,
        
        'last_7_dates': last_7_dates,
        'project': project
    }
    return render(request, 'dashboard/index.html', context)


def profile(request, slug):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(
                request,
                'Your password was successfully changed!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'dashboard/profile.html', {
        'form': form
    })


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface(request, slug):
    UserModel = get_user_model()
    users = UserModel.objects.all().order_by('date_joined')
    return render(
        request,
        'dashboard/admin.html',
        {
            'users': users
        }
    )

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface_update(request, slug):
    mode = request.GET.get('mode')
    user_id = request.GET.get('user')
    if user_id:
        UserModel = get_user_model()
        user = UserModel.objects.get(id=user_id)
    if request.method == 'GET':
        if mode == 'change_status':
            user.is_active = not user.is_active
            user.save()
    elif request.method == 'POST':
        if mode == 'delete':
            try:
                user.delete()
                messages.add_message(
                    request,
                    messages.INFO,
                    f'User {user.username} successfully deleted.'
                )
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False}
        elif mode == 'update':
            try:
                response = json.loads(request.body)
                role = response.get('role')
                change_password = response.get('change_password')
                clear_roles(user)
                assign_role(user, role)
                if change_password:
                    user.set_password(change_password)
                    user.save()
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False, 'error': str(e)}
        elif mode == 'create':
            try:
                response = json.loads(request.body)
                if not response.get('password'):
                    messageData = {'status': False, 'error': 'Empty passwords are not allowed'}
                    return JsonResponse(messageData)
                UserModel = get_user_model()
                user = UserModel.objects.create_user(
                    username=response.get('username'),
                    password=response.get('password')
                )
                assign_role(user, response.get('role'))
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False, 'error': str(e)}
        return JsonResponse(messageData)
    return HttpResponseRedirect(reverse('admin_interface', kwargs={'slug': slug}))


@receiver(user_logged_out)
def on_user_logged_out(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'You have been successfully logged out. Thank you ' +
        'for using webGuard.')


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'Hi @' +
        request.user.username +
        ' welcome back!')


def search(request, slug):
    return render(request, 'dashboard/search.html')


def four_oh_four(request):
    return render(request, '404.html')


def projects(request, slug):
    context = {}
    context['projects'] = Project.objects.all()
    return render(request, 'dashboard/projects.html', context)


def delete_project(request, id):
    obj = get_object_or_404(Project, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {
            'status': 'true'
        }
        messages.add_message(
            request,
            messages.INFO,
            'Project successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Project could not be deleted!')
    return JsonResponse(responseData)


def onboarding(request):
    context = {}
    error = ''

    # check is any projects exists, then redirect to project list else onboarding
    project = Project.objects.first()

    if project:
        slug = project.slug
        return HttpResponseRedirect(reverse('dashboardIndex', kwargs={'slug': slug}))

    if request.method == "POST":
        project_name = request.POST.get('project_name')
        slug = slugify(project_name)
        create_username = request.POST.get('create_username')
        create_password = request.POST.get('create_password')
        create_user_role = request.POST.get('create_user_role')
        key_openai = request.POST.get('key_openai')
        key_netlas = request.POST.get('key_netlas')
        key_chaos = request.POST.get('key_chaos')
        key_hackerone = request.POST.get('key_hackerone')
        username_hackerone = request.POST.get('username_hackerone')
        bug_bounty_mode = request.POST.get('bug_bounty_mode') == 'on'

        insert_date = timezone.now()

        try:
            Project.objects.create(
                name=project_name,
                slug=slug,
                insert_date=insert_date
            )
        except Exception as e:
            error = ' Could not create project, Error: ' + str(e)


        # update currently logged in user's preferences for bug bounty mode
        user_preferences, _ = UserPreferences.objects.get_or_create(user=request.user)
        user_preferences.bug_bounty_mode = bug_bounty_mode
        user_preferences.save()


        try:
            if create_username and create_password and create_user_role:
                UserModel = get_user_model()
                new_user = UserModel.objects.create_user(
                    username=create_username,
                    password=create_password
                )
                assign_role(new_user, create_user_role)


                # initially bug bounty mode is enabled for new user as selected for current user
                new_user_preferences, _ = UserPreferences.objects.get_or_create(user=new_user)
                new_user_preferences.bug_bounty_mode = bug_bounty_mode
                new_user_preferences.save()
                
        except Exception as e:
            error = ' Could not create User, Error: ' + str(e)

        if key_openai:
            openai_api_key = OpenAiAPIKey.objects.first()
            if openai_api_key:
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if key_netlas:
            netlas_api_key = NetlasAPIKey.objects.first()
            if netlas_api_key:
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

        if key_chaos:
            chaos_api_key = ChaosAPIKey.objects.first()
            if chaos_api_key:
                chaos_api_key.key = key_chaos
                chaos_api_key.save()
            else:
                ChaosAPIKey.objects.create(key=key_chaos)

        if key_hackerone and username_hackerone:
            hackerone_api_key = HackerOneAPIKey.objects.first()
            if hackerone_api_key:
                hackerone_api_key.username = username_hackerone
                hackerone_api_key.key = key_hackerone
                hackerone_api_key.save()
            else:
                HackerOneAPIKey.objects.create(
                    username=username_hackerone, 
                    key=key_hackerone
                )

    context['error'] = error
    

    context['openai_key'] = OpenAiAPIKey.objects.first()
    context['netlas_key'] = NetlasAPIKey.objects.first()
    context['chaos_key'] = ChaosAPIKey.objects.first()
    context['hackerone_key'] = HackerOneAPIKey.objects.first().key if HackerOneAPIKey.objects.first() else ''
    context['hackerone_username'] = HackerOneAPIKey.objects.first().username if HackerOneAPIKey.objects.first() else ''

    context['user_preferences'], _ = UserPreferences.objects.get_or_create(
        user=request.user
    )

    return render(request, 'dashboard/onboarding.html', context)



def list_bountyhub_programs(request, slug):
    context = {}
    # get parameter to device which platform is being requested
    platform = request.GET.get('platform') or 'hackerone'
    context['platform'] = platform.capitalize()
    
    return render(request, 'dashboard/bountyhub_programs.html', context)