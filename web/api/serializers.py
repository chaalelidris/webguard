from dashboard.models import *
from django.contrib.humanize.templatetags.humanize import (naturalday, naturaltime)
from django.db.models import F, JSONField, Value
from webGuard.common_func import *
from rest_framework import serializers
from targetApp.models import *
from dashboard.models import InAppNotification


class HackerOneProgramAttributesSerializer(serializers.Serializer):
	"""
		Serializer for HackerOne Program
		IMP: THIS is not a model serializer, programs will not be stored in db
		due to ever changing nature of programs, rather cache will be used on these serializers
	"""
	handle = serializers.CharField(required=False)
	name = serializers.CharField(required=False)
	currency = serializers.CharField(required=False)
	submission_state = serializers.CharField(required=False)
	triage_active = serializers.BooleanField(allow_null=True, required=False)
	state = serializers.CharField(required=False)
	started_accepting_at = serializers.DateTimeField(required=False)
	bookmarked = serializers.BooleanField(required=False)
	allows_bounty_splitting = serializers.BooleanField(required=False)
	offers_bounties = serializers.BooleanField(required=False)
	open_scope = serializers.BooleanField(allow_null=True, required=False)
	fast_payments = serializers.BooleanField(allow_null=True, required=False)
	gold_standard_safe_harbor = serializers.BooleanField(allow_null=True, required=False)

	def to_representation(self, instance):
		return {key: value for key, value in instance.items()}


class HackerOneProgramSerializer(serializers.Serializer):
	id = serializers.CharField()
	type = serializers.CharField()
	attributes = HackerOneProgramAttributesSerializer()



class InAppNotificationSerializer(serializers.ModelSerializer):
	class Meta:
		model = InAppNotification
		fields = [
			'id', 
			'title', 
			'description', 
			'icon', 
			'is_read', 
			'created_at', 
			'notification_type', 
			'status',
			'redirect_link',
			'open_in_new_tab',
			'project'
		]
		read_only_fields = ['id', 'created_at']

	def get_project_name(self, obj):
		return obj.project.name if obj.project else None


class SearchHistorySerializer(serializers.ModelSerializer):
	class Meta:
		model = SearchHistory
		fields = ['query']


class DomainSerializer(serializers.ModelSerializer):
	vuln_count = serializers.SerializerMethodField()
	organization = serializers.SerializerMethodField()
	most_recent_scan = serializers.SerializerMethodField()
	insert_date = serializers.SerializerMethodField()
	insert_date_humanized = serializers.SerializerMethodField()
	start_scan_date = serializers.SerializerMethodField()
	start_scan_date_humanized = serializers.SerializerMethodField()

	class Meta:
		model = Domain
		fields = '__all__'
		depth = 2

	def get_vuln_count(self, obj):
		try:
			return obj.vuln_count
		except:
			return None

	def get_organization(self, obj):
		if Organization.objects.filter(domains__id=obj.id).exists():
			return [org.name for org in Organization.objects.filter(domains__id=obj.id)]

	def get_most_recent_scan(self, obj):
		return obj.get_recent_scan_id()

	def get_insert_date(self, obj):
		return naturalday(obj.insert_date).title()

	def get_insert_date_humanized(self, obj):
		return naturaltime(obj.insert_date).title()

	def get_start_scan_date(self, obj):
		if obj.start_scan_date:
			return naturalday(obj.start_scan_date).title()

	def get_start_scan_date_humanized(self, obj):
		if obj.start_scan_date:
			return naturaltime(obj.start_scan_date).title()







class OrganizationSerializer(serializers.ModelSerializer):

	class Meta:
		model = Organization
		fields = '__all__'



class OrganizationTargetsSerializer(serializers.ModelSerializer):

	class Meta:
		model = Domain
		fields = [
			'name'
		]


class DorkCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	type = serializers.CharField()



ds = ['http_url']


