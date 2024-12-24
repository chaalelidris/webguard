import re
import socket
import logging
import requests
import validators
import requests

from ipaddress import IPv4Network
from django.db.models import CharField, Count, F, Q, Value
from django.utils import timezone
from packaging import version
from django.template.defaultfilters import slugify
from datetime import datetime
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_204_NO_CONTENT, HTTP_202_ACCEPTED
from rest_framework.decorators import action
from django.core.exceptions import ObjectDoesNotExist
from django.core.cache import cache


from dashboard.models import *
from webGuard.celery import app
from webGuard.common_func import *
from webGuard.database_utils import *
from webGuard.definitions import ABORTED_TASK
from webGuard.tasks import *
from webGuard.llm import *
from webGuard.utilities import is_safe_path
from targetApp.models import *
from api.shared_api_tasks import import_hackerone_programs_task, sync_bookmarked_programs_task
from .serializers import *


logger = logging.getLogger(__name__)


class ToggleBugBountyModeView(APIView):
	"""
		This class manages the user bug bounty mode
	"""
	def post(self, request, *args, **kwargs):
		user_preferences = get_object_or_404(UserPreferences, user=request.user)
		user_preferences.bug_bounty_mode = not user_preferences.bug_bounty_mode
		user_preferences.save()
		return Response({
			'bug_bounty_mode': user_preferences.bug_bounty_mode
		}, status=status.HTTP_200_OK)


class HackerOneProgramViewSet(viewsets.ViewSet):
	"""
		This class manages the HackerOne Program model, 
		provides basic fetching of programs and caching
	"""
	CACHE_KEY = 'hackerone_programs'
	CACHE_TIMEOUT = 60 * 30 # 30 minutes
	PROGRAM_CACHE_KEY = 'hackerone_program_{}'

	API_BASE = 'https://api.hackerone.com/v1/hackers'

	ALLOWED_ASSET_TYPES = ["WILDCARD", "DOMAIN", "IP_ADDRESS", "CIDR", "URL"]

	def list(self, request):
		try:
			sort_by = request.query_params.get('sort_by', 'age')
			sort_order = request.query_params.get('sort_order', 'desc')

			programs = self.get_cached_programs()

			if sort_by == 'name':
				programs = sorted(programs, key=lambda x: x['attributes']['name'].lower(), 
						reverse=(sort_order.lower() == 'desc'))
			elif sort_by == 'reports':
				programs = sorted(programs, key=lambda x: x['attributes'].get('number_of_reports_for_user', 0), 
						reverse=(sort_order.lower() == 'desc'))
			elif sort_by == 'age':
				programs = sorted(programs, 
					key=lambda x: datetime.strptime(x['attributes'].get('started_accepting_at', '1970-01-01T00:00:00.000Z'), '%Y-%m-%dT%H:%M:%S.%fZ'), 
					reverse=(sort_order.lower() == 'desc')
				)

			serializer = HackerOneProgramSerializer(programs, many=True)
			return Response(serializer.data)
		except Exception as e:
			return self.handle_exception(e)
	
	def get_api_credentials(self):
		try:
			api_key = HackerOneAPIKey.objects.first()
			if not api_key:
				raise ObjectDoesNotExist("HackerOne API credentials not found")
			return api_key.username, api_key.key
		except ObjectDoesNotExist:
			raise Exception("HackerOne API credentials not configured")

	@action(detail=False, methods=['get'])
	def bookmarked_programs(self, request):
		try:
			# do not cache bookmarked programs due to the user specific nature
			programs = self.fetch_programs_from_hackerone()
			bookmarked = [p for p in programs if p['attributes']['bookmarked']]
			serializer = HackerOneProgramSerializer(bookmarked, many=True)
			return Response(serializer.data)
		except Exception as e:
			return self.handle_exception(e)
	
	@action(detail=False, methods=['get'])
	def bounty_programs(self, request):
		try:
			programs = self.get_cached_programs()
			bounty_programs = [p for p in programs if p['attributes']['offers_bounties']]
			serializer = HackerOneProgramSerializer(bounty_programs, many=True)
			return Response(serializer.data)
		except Exception as e:
			return self.handle_exception(e)

	def get_cached_programs(self):
		programs = cache.get(self.CACHE_KEY)
		if programs is None:
			programs = self.fetch_programs_from_hackerone()
			cache.set(self.CACHE_KEY, programs, self.CACHE_TIMEOUT)
		return programs

	def fetch_programs_from_hackerone(self):
		url = f'{self.API_BASE}/programs?page[size]=100'
		headers = {'Accept': 'application/json'}
		all_programs = []
		try:
			username, api_key = self.get_api_credentials()
		except Exception as e:
			raise Exception("API credentials error: " + str(e))

		while url:
			response = requests.get(
				url,
				headers=headers,
				auth=(username, api_key)
			)

			if response.status_code == 401:
				raise Exception("Invalid API credentials")
			elif response.status_code != 200:
				raise Exception(f"HackerOne API request failed with status code {response.status_code}")

			data = response.json()
			all_programs.extend(data['data'])
			
			url = data['links'].get('next')

		return all_programs

	@action(detail=False, methods=['post'])
	def refresh_cache(self, request):
		try:
			programs = self.fetch_programs_from_hackerone()
			cache.set(self.CACHE_KEY, programs, self.CACHE_TIMEOUT)
			return Response({"status": "Cache refreshed successfully"})
		except Exception as e:
			return self.handle_exception(e)
	
	@action(detail=True, methods=['get'])
	def program_details(self, request, pk=None):
		try:
			program_handle = pk
			cache_key = self.PROGRAM_CACHE_KEY.format(program_handle)
			program_details = cache.get(cache_key)

			if program_details is None:
				program_details = self.fetch_program_details_from_hackerone(program_handle)
				if program_details:
					cache.set(cache_key, program_details, self.CACHE_TIMEOUT)

			if program_details:
				filtered_scopes = [
					scope for scope in program_details.get('relationships', {}).get('structured_scopes', {}).get('data', [])
					if scope.get('attributes', {}).get('asset_type') in self.ALLOWED_ASSET_TYPES
				]

				program_details['relationships']['structured_scopes']['data'] = filtered_scopes

				return Response(program_details)
			else:
				return Response({"error": "Program not found"}, status=status.HTTP_404_NOT_FOUND)
		except Exception as e:
			return self.handle_exception(e)

	def fetch_program_details_from_hackerone(self, program_handle):
		url = f'{self.API_BASE}/programs/{program_handle}'
		headers = {'Accept': 'application/json'}
		try:
			username, api_key = self.get_api_credentials()
		except Exception as e:
			raise Exception("API credentials error: " + str(e))

		response = requests.get(
			url,
			headers=headers,
			auth=(username, api_key)
		)

		if response.status_code == 401:
			raise Exception("Invalid API credentials")
		elif response.status_code == 200:
			return response.json()
		else:
			return None
		
	@action(detail=False, methods=['post'])
	def import_programs(self, request):
		try:
			project_slug = request.query_params.get('project_slug')
			if not project_slug:
				return Response({"error": "Project slug is required"}, status=status.HTTP_400_BAD_REQUEST)
			handles = request.data.get('handles', [])

			if not handles:
				return Response({"error": "No program handles provided"}, status=status.HTTP_400_BAD_REQUEST)

			import_hackerone_programs_task.delay(handles, project_slug)

			create_inappnotification(
				title="HackerOne Program Import Started",
				description=f"Import process for {len(handles)} program(s) has begun.",
				notification_type=PROJECT_LEVEL_NOTIFICATION,
				project_slug=project_slug,
				icon="mdi-download",
				status='info'
			)

			return Response({"message": f"Import process for {len(handles)} program(s) has begun."}, status=status.HTTP_202_ACCEPTED)
		except Exception as e:
			return self.handle_exception(e)
	
	@action(detail=False, methods=['get'])
	def sync_bookmarked(self, request):
		try:
			project_slug = request.query_params.get('project_slug')
			if not project_slug:
				return Response({"error": "Project slug is required"}, status=status.HTTP_400_BAD_REQUEST)

			sync_bookmarked_programs_task.delay(project_slug)

			create_inappnotification(
				title="HackerOne Bookmarked Programs Sync Started",
				description="Sync process for bookmarked programs has begun.",
				notification_type=PROJECT_LEVEL_NOTIFICATION,
				project_slug=project_slug,
				icon="mdi-sync",
				status='info'
			)

			return Response({"message": "Sync process for bookmarked programs has begun."}, status=status.HTTP_202_ACCEPTED)
		except Exception as e:
			return self.handle_exception(e)

	def handle_exception(self, exc):
		if isinstance(exc, ObjectDoesNotExist):
			return Response({"error": "HackerOne API credentials not configured"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
		elif str(exc) == "Invalid API credentials":
			return Response({"error": "Invalid HackerOne API credentials"}, status=status.HTTP_401_UNAUTHORIZED)
		else:
			return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class InAppNotificationManagerViewSet(viewsets.ModelViewSet):
	"""
		This class manages the notification model, provided CRUD operation on notif model
		such as read notif, clear all, fetch all notifications etc
	"""
	serializer_class = InAppNotificationSerializer
	pagination_class = None

	def get_queryset(self):
		# we will see later if user based notif is needed
		# return InAppNotification.objects.filter(user=self.request.user)
		project_slug = self.request.query_params.get('project_slug')
		queryset = InAppNotification.objects.all()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		return queryset.order_by('-created_at')

	@action(detail=False, methods=['post'])
	def mark_all_read(self, request):
		# marks all notification read
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()

		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		queryset.update(is_read=True)
		return Response(status=HTTP_204_NO_CONTENT)

	@action(detail=True, methods=['post'])
	def mark_read(self, request, pk=None):
		# mark individual notification read when cliked
		notification = self.get_object()
		notification.is_read = True
		notification.save()
		return Response(status=HTTP_204_NO_CONTENT)

	@action(detail=False, methods=['get'])
	def unread_count(self, request):
		# this fetches the count for unread notif mainly for the badge
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		count = queryset.filter(is_read=False).count()
		return Response({'count': count})

	@action(detail=False, methods=['post'])
	def clear_all(self, request):
		# when clicked on the clear button this must be called to clear all notif
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		queryset.delete()
		return Response(status=HTTP_204_NO_CONTENT)


class OllamaManager(APIView):
	def get(self, request):
		"""
		API to download Ollama Models
		sends a POST request to download the model
		"""
		req = self.request
		model_name = req.query_params.get('model')
		response = {
			'status': False
		}
		try:
			pull_model_api = f'{OLLAMA_INSTANCE}/api/pull'
			_response = requests.post(
				pull_model_api, 
				json={
					'name': model_name,
					'stream': False
				}
			).json()
			if _response.get('error'):
				response['status'] = False
				response['error'] = _response.get('error')
			else:
				response['status'] = True
		except Exception as e:
			response['error'] = str(e)		
		return Response(response)
	
	def delete(self, request):
		req = self.request
		model_name = req.query_params.get('model')
		delete_model_api = f'{OLLAMA_INSTANCE}/api/delete'
		response = {
			'status': False
		}
		try:
			_response = requests.delete(
				delete_model_api, 
				json={
					'name': model_name
				}
			).json()
			if _response.get('error'):
				response['status'] = False
				response['error'] = _response.get('error')
			else:
				response['status'] = True
		except Exception as e:
			response['error'] = str(e)
		return Response(response)
	
	def put(self, request):
		req = self.request
		model_name = req.query_params.get('model')
		# check if model_name is in DEFAULT_GPT_MODELS
		response = {
			'status': False
		}
		use_ollama = True
		if any(model['name'] == model_name for model in DEFAULT_GPT_MODELS):
			use_ollama = False
		try:
			OllamaSettings.objects.update_or_create(
				defaults={
					'selected_model': model_name,
					'use_ollama': use_ollama
				},
				id=1
			)
			response['status'] = True
		except Exception as e:
			response['error'] = str(e)
		return Response(response)




class CreateProjectApi(APIView):
	def get(self, request):
		req = self.request
		project_name = req.query_params.get('name')
		slug = slugify(project_name)
		insert_date = timezone.now()

		try:
			project = Project.objects.create(
				name=project_name,
				slug=slug,
				insert_date =insert_date
			)
			response = {
				'status': True,
				'project_name': project_name
			}
			return Response(response)
		except Exception as e:
			response = {
				'status': False,
				'error': str(e)
			}
			return Response(response, status=HTTP_400_BAD_REQUEST)



class QueryInterestingSubdomains(APIView):
	def get(self, request):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		domain_id = req.query_params.get('target_id')

		if scan_id:
			queryset = get_interesting_subdomains(scan_history=scan_id)
		elif domain_id:
			queryset = get_interesting_subdomains(domain_id=domain_id)
		else:
			queryset = get_interesting_subdomains()

		queryset = queryset.distinct('name')

		return Response(InterestingSubdomainSerializer(queryset, many=True).data)


class ListTargetsDatatableViewSet(viewsets.ModelViewSet):
	queryset = Domain.objects.all()
	serializer_class = DomainSerializer

	def get_queryset(self):
		slug = self.request.GET.get('slug', None)
		if slug:
			self.queryset = self.queryset.filter(project__slug=slug)
		return self.queryset

	def filter_queryset(self, qs):
		qs = self.queryset.filter()
		search_value = self.request.GET.get(u'search[value]', None)
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		if search_value or _order_col or _order_direction:
			order_col = 'id'
			if _order_col == '2':
				order_col = 'name'
			elif _order_col == '4':
				order_col = 'insert_date'
			elif _order_col == '5':
				order_col = 'start_scan_date'
				if _order_direction == 'desc':
					return qs.order_by(F('start_scan_date').desc(nulls_last=True))
				return qs.order_by(F('start_scan_date').asc(nulls_last=True))


			if _order_direction == 'desc':
				order_col = f'-{order_col}'

			qs = self.queryset.filter(
				Q(name__icontains=search_value) |
				Q(description__icontains=search_value) |
				Q(domains__name__icontains=search_value)
			)
			return qs.order_by(order_col)

		return qs.order_by('-id')
class WafDetector(APIView):
	def get(self, request):
		req = self.request
		url= req.query_params.get('url')
		response = {}
		response['status'] = False

		# validate url as a first step to avoid command injection
		if not (validators.url(url) or validators.domain(url)):
			response['message'] = 'Invalid Domain/URL provided!'
			return Response(response)
		
		wafw00f_command = f'wafw00f {url}'
		_, output = run_command(wafw00f_command, remove_ansi_sequence=True)
		regex = r"behind (.*?) WAF"
		group = re.search(regex, output)
		if group:
			response['status'] = True
			response['results'] = group.group(1)
		else:
			response['message'] = 'Could not detect any WAF!'

		return Response(response)


class SearchHistoryView(APIView):
	def get(self, request):
		req = self.request

		response = {}
		response['status'] = False

		scan_history = SearchHistory.objects.all().order_by('-id')[:5]

		if scan_history:
			response['status'] = True
			response['results'] = SearchHistorySerializer(scan_history, many=True).data

		return Response(response)






class CVEDetails(APIView):
	def get(self, request):
		req = self.request

		cve_id = req.query_params.get('cve_id')

		if not cve_id:
			return Response({'status': False, 'message': 'CVE ID not provided'})

		response = requests.get('https://cve.circl.lu/api/cve/' + cve_id)

		if response.status_code != 200:
			return  Response({'status': False, 'message': 'Unknown Error Occured!'})

		if not response.json():
			return  Response({'status': False, 'message': 'CVE ID does not exists.'})

		return Response({'status': True, 'result': response.json()})





class AddTarget(APIView):
	def post(self, request):
		req = self.request
		data = req.data
		h1_team_handle = data.get('h1_team_handle')
		description = data.get('description')
		domain_name = data.get('domain_name')
		# remove wild card from domain
		domain_name = domain_name.replace('*', '')
		# if domain_name begins with . remove that
		if domain_name.startswith('.'):
			domain_name = domain_name[1:]
		organization_name = data.get('organization')
		slug = data.get('slug')

		# Validate domain name
		if not validators.domain(domain_name):
			return Response({'status': False, 'message': 'Invalid domain or IP'})

		status = bulk_import_targets(
			targets=[{
				'name': domain_name,
				'description': description,
			}],
			organization_name=organization_name,
			h1_team_handle=h1_team_handle,
			project_slug=slug
		)

		if status:
			return Response({
				'status': True,
				'message': 'Domain successfully added as target !',
				'domain_name': domain_name,
				# 'domain_id': domain.id
			})
		return Response({
			'status': False,
			'message': 'Failed to add as target !'
		})
class DeleteMultipleRows(APIView):
	def post(self, request):
		req = self.request
		data = req.data

		try:
			if data['type'] == 'organization':
				for row in data['rows']:
					Organization.objects.get(id=row).delete()
			response = True
		except Exception as e:
			response = False

		return Response({'status': response})



class ListInterestingKeywords(APIView):
	def get(self, request, format=None):
		req = self.request
		keywords = get_lookup_keywords()
		return Response(keywords)


class WebguardUpdateCheck(APIView):
	def get(self, request):
		req = self.request
		github_api = \
			'https://api.github.com/repos/yogeshojha/webguard/releases'
		response = requests.get(github_api).json()
		if 'message' in response:
			return Response({'status': False, 'message': 'RateLimited'})

		return_response = {}

		# get current version_number
		# remove quotes from current_version
		current_version = WEBGUARD_CURRENT_VERSION

		# for consistency remove v from both if exists
		latest_version = re.search(r'v(\d+\.)?(\d+\.)?(\*|\d+)',
								   ((response[0]['name'
								   ])[1:] if response[0]['name'][0] == 'v'
									else response[0]['name']))

		latest_version = latest_version.group(0) if latest_version else None

		if not latest_version:
			latest_version = re.search(r'(\d+\.)?(\d+\.)?(\*|\d+)',
										((response[0]['name'
										])[1:] if response[0]['name'][0]
										== 'v' else response[0]['name']))
			if latest_version:
				latest_version = latest_version.group(0)

		return_response['status'] = True
		return_response['latest_version'] = latest_version
		return_response['current_version'] = current_version
		is_version_update_available = version.parse(current_version) < version.parse(latest_version)

		# if is_version_update_available then we should create inapp notification
		create_inappnotification(
			title='WebGuard Updated',
			description=f'System Updated to latest version.',
			notification_type=SYSTEM_LEVEL_NOTIFICATION,
			project_slug=None,
			icon='mdi-update',
			redirect_link='#',
			open_in_new_tab=True
		)

		return_response['update_available'] = is_version_update_available
		if is_version_update_available:
			return_response['changelog'] = response[0]['body']

		return Response(return_response)


class UninstallTool(APIView):
	def get(self, request):
		req = self.request
		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')

		if tool_id:
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			tool = InstalledExternalTool.objects.get(name=tool_name)


		if tool.is_default:
			return Response({'status': False, 'message': 'Default tools can not be uninstalled'})

		# check install instructions, if it is installed using go, then remove from go bin path,
		# else try to remove from github clone path

		# getting tool name is tricky!

		if 'go install' in tool.install_command:
			tool_name = tool.install_command.split('/')[-1].split('@')[0]
			uninstall_command = 'rm /go/bin/' + tool_name
		elif 'git clone' in tool.install_command:
			tool_name = tool.install_command[:-1] if tool.install_command[-1] == '/' else tool.install_command
			tool_name = tool_name.split('/')[-1]
			uninstall_command = 'rm -rf ' + tool.github_clone_path
		else:
			return Response({'status': False, 'message': 'Cannot uninstall tool!'})

		run_command(uninstall_command)
		run_command.apply_async(args=(uninstall_command,))

		tool.delete()

		return Response({'status': True, 'message': 'Uninstall Tool Success'})


class UpdateTool(APIView):
	def get(self, request):
		req = self.request
		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')

		if tool_id:
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			tool = InstalledExternalTool.objects.get(name=tool_name)

		# if git clone was used for installation, then we must use git pull inside project directory,
		# otherwise use the same command as given

		update_command = tool.update_command.lower()

		if not update_command:
			return Response({'status': False, 'message': tool.name + 'has missing update command! Cannot update the tool.'})
		elif update_command == 'git pull':
			tool_name = tool.install_command[:-1] if tool.install_command[-1] == '/' else tool.install_command
			tool_name = tool_name.split('/')[-1]
			update_command = 'cd /usr/src/github/' + tool_name + ' && git pull && cd -'

		
		try:
			run_command(update_command, shell=True)
			run_command.apply_async(args=[update_command], kwargs={'shell': True})
			return Response({'status': True, 'message': tool.name + ' updated successfully.'})
		except Exception as e:
			logger.error(str(e))
			return Response({'status': False, 'message': str(e)})

class GetExternalToolCurrentVersion(APIView):
	def get(self, request):
		req = self.request
		# toolname is also the command
		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')
		# can supply either tool id or tool_name

		tool = None

		if tool_id:
			if not InstalledExternalTool.objects.filter(id=tool_id).exists():
				return Response({'status': False, 'message': 'Tool Not found'})
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			if not InstalledExternalTool.objects.filter(name=tool_name).exists():
				return Response({'status': False, 'message': 'Tool Not found'})
			tool = InstalledExternalTool.objects.get(name=tool_name)

		if not tool.version_lookup_command:
			return Response({'status': False, 'message': 'Version Lookup command not provided.'})

		version_number = None
		_, stdout = run_command(tool.version_lookup_command)
		if tool.version_match_regex:
			version_number = re.search(re.compile(tool.version_match_regex), str(stdout))
		else:
			version_match_regex = r'(?i:v)?(\d+(?:\.\d+){2,})'
			version_number = re.search(version_match_regex, str(stdout))
		if not version_number:
			return Response({'status': False, 'message': 'Invalid version lookup command.'})

		return Response({'status': True, 'version_number': version_number.group(0), 'tool_name': tool.name})



class GithubToolCheckGetLatestRelease(APIView):
	def get(self, request):
		req = self.request

		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')

		if not InstalledExternalTool.objects.filter(id=tool_id).exists():
			return Response({'status': False, 'message': 'Tool Not found'})

		if tool_id:
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			tool = InstalledExternalTool.objects.get(name=tool_name)

		if not tool.github_url:
			return Response({'status': False, 'message': 'Github URL is not provided, Cannot check updates'})

		# if tool_github_url has https://github.com/ remove and also remove trailing /
		tool_github_url = tool.github_url.replace('http://github.com/', '').replace('https://github.com/', '')
		tool_github_url = remove_lead_and_trail_slash(tool_github_url)
		github_api = f'https://api.github.com/repos/{tool_github_url}/releases'
		response = requests.get(github_api).json()
		# check if api rate limit exceeded
		if 'message' in response and response['message'] == 'RateLimited':
			return Response({'status': False, 'message': 'RateLimited'})
		elif 'message' in response and response['message'] == 'Not Found':
			return Response({'status': False, 'message': 'Not Found'})
		elif not response:
			return Response({'status': False, 'message': 'Not Found'})

		# only send latest release
		response = response[0]

		api_response = {
			'status': True,
			'url': response['url'],
			'id': response['id'],
			'name': response['name'],
			'changelog': response['body'],
		}
		return Response(api_response)



class Whois(APIView):
	def get(self, request):
		req = self.request
		target = req.query_params.get('target')
		if not target:
			return Response({'status': False, 'message': 'Target IP/Domain required!'})
		if not (validators.domain(target) or validators.ipv4(target) or validators.ipv6(target)):
			print(f'Ip address or domain "{target}" did not pass validator.')
			return Response({'status': False, 'message': 'Invalid domain or IP'})
		is_force_update = req.query_params.get('is_reload')
		is_force_update = True if is_force_update and 'true' == is_force_update.lower() else False
		task = query_whois.apply_async(args=(target,is_force_update))
		response = task.wait()
		return Response(response)


class ReverseWhois(APIView):
	def get(self, request):
		req = self.request
		lookup_keyword = req.query_params.get('lookup_keyword')
		task = query_reverse_whois.apply_async(args=(lookup_keyword,))
		response = task.wait()
		return Response(response)


class DomainIPHistory(APIView):
	def get(self, request):
		req = self.request
		domain = req.query_params.get('domain')
		task = query_ip_history.apply_async(args=(domain,))
		response = task.wait()
		return Response(response)


class CMSDetector(APIView):
	def get(self, request):
		req = self.request
		url = req.query_params.get('url')
		#save_db = True if 'save_db' in req.query_params else False
		response = {'status': False}

		if not (validators.url(url) or validators.domain(url)):
			response['message'] = 'Invalid Domain/URL provided!'
			return Response(response)

		try:
			# response = get_cms_details(url)
			response = {}
			cms_detector_command = f'python3 /usr/src/github/CMSeeK/cmseek.py'
			cms_detector_command += ' --random-agent --batch --follow-redirect'
			cms_detector_command += f' -u {url}'

			_, output = run_command(cms_detector_command, remove_ansi_sequence=True)

			response['message'] = 'Could not detect CMS!'

			parsed_url = urlparse(url)

			domain_name = parsed_url.hostname
			port = parsed_url.port

			find_dir = domain_name

			if port:
				find_dir += '_{}'.format(port)
			# look for result path in output
			path_regex = r"Result: (\/usr\/src[^\"\s]*)"
			match = re.search(path_regex, output)
			if match:
				cms_json_path = match.group(1)
				if os.path.isfile(cms_json_path):
					cms_file_content = json.loads(open(cms_json_path, 'r').read())
					if not cms_file_content.get('cms_id'):
						return response
					response = {}
					response = cms_file_content
					response['status'] = True
					try:
						# remove results
						cms_dir_path = os.path.dirname(cms_json_path)
						shutil.rmtree(cms_dir_path)
					except Exception as e:
						logger.error(e)
					return Response(response)
			return Response(response)
		except Exception as e:
			response = {'status': False, 'message': str(e)}
			return Response(response)


class IPToDomain(APIView):
	def get(self, request):
		req = self.request
		ip_address = req.query_params.get('ip_address')
		if not ip_address:
			return Response({
				'status': False,
				'message': 'IP Address Required'
			})
		try:
			logger.info(f'Resolving IP address {ip_address} ...')
			resolved_ips = []
			for ip in IPv4Network(ip_address, False):
				domains = []
				ips = []
				try:
					(domain, domains, ips) = socket.gethostbyaddr(str(ip))
				except socket.herror:
					logger.info(f'No PTR record for {ip_address}')
					domain = str(ip)
				if domain not in domains:
					domains.append(domain)
				resolved_ips.append({'ip': str(ip),'domain': domain, 'domains': domains, 'ips': ips})
			response = {
				'status': True,
				'orig': ip_address,
				'ip_address': resolved_ips,
			}
		except Exception as e:
			logger.exception(e)
			response = {
				'status': False,
				'ip_address': ip_address,
				'message': f'Exception {e}'
			}
		finally:
			return Response(response)


class VulnerabilityReport(APIView):
	def get(self, request):
		req = self.request
		vulnerability_id = req.query_params.get('vulnerability_id')
		return Response({"status": send_hackerone_report(vulnerability_id)})


class GetFileContents(APIView):
	def get(self, request, format=None):
		req = self.request
		name = req.query_params.get('name')

		response = {}
		response['status'] = False

		if 'nuclei_config' in req.query_params:
			path = "/root/.config/nuclei/config.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'subfinder_config' in req.query_params:
			path = "/root/.config/subfinder/config.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'naabu_config' in req.query_params:
			path = "/root/.config/naabu/config.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'theharvester_config' in req.query_params:
			path = "/usr/src/github/theHarvester/api-keys.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'amass_config' in req.query_params:
			path = "/root/.config/amass.ini"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'gf_pattern' in req.query_params:
			basedir = '/root/.gf'
			path = f'/root/.gf/{name}.json'
			if is_safe_path(basedir, path) and os.path.exists(path):
				content = open(path, "r").read()
				response['status'] = True
				response['content'] = content
			else:
				response['message'] = "Invalid path!"
				response['status'] = False
			return Response(response)


		if 'nuclei_template' in req.query_params:
			safe_dir = '/root/nuclei-templates'
			path = f'/root/nuclei-templates/{name}'
			if is_safe_path(safe_dir, path) and os.path.exists(path):
				content = open(path.format(name), "r").read()
				response['status'] = True
				response['content'] = content
			else:
				response['message'] = 'Invalid Path!'
				response['status'] = False
			return Response(response)

		response['message'] = 'Invalid Query Params'
		return Response(response)




class ListEngines(APIView):
	def get(self, request, format=None):
		req = self.request
		engines = EngineType.objects.order_by('engine_name').all()
		engine_serializer = EngineSerializer(engines, many=True)
		return Response({'engines': engine_serializer.data})


class ListOrganizations(APIView):
	def get(self, request, format=None):
		req = self.request
		organizations = Organization.objects.all()
		organization_serializer = OrganizationSerializer(organizations, many=True)
		return Response({'organizations': organization_serializer.data})


class ListTargetsInOrganization(APIView):
	def get(self, request, format=None):
		req = self.request
		organization_id = req.query_params.get('organization_id')
		organization = Organization.objects.filter(id=organization_id)
		targets = Domain.objects.filter(domains__in=organization)
		organization_serializer = OrganizationSerializer(organization, many=True)
		targets_serializer = OrganizationTargetsSerializer(targets, many=True)
		return Response({'organization': organization_serializer.data, 'domains': targets_serializer.data})


class ListTargetsWithoutOrganization(APIView):
	def get(self, request, format=None):
		req = self.request
		targets = Domain.objects.exclude(domains__in=Organization.objects.all())
		targets_serializer = OrganizationTargetsSerializer(targets, many=True)
		return Response({'domains': targets_serializer.data})

class ListOsintUsers(APIView):
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			documents = MetaFinderDocument.objects.filter(scan_history__id=scan_id).exclude(author__isnull=True).values('author').distinct()
			serializer = MetafinderUserSerializer(documents, many=True)
			return Response({"users": serializer.data})


class ListMetadata(APIView):
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			documents = MetaFinderDocument.objects.filter(scan_history__id=scan_id).distinct()
			serializer = MetafinderDocumentSerializer(documents, many=True)
			return Response({"metadata": serializer.data})