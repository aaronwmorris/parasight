from django.contrib import admin
from django.db.models import Count
from django.db.models import F
from django.db.models import Q
from django.utils.safestring import mark_safe
from django.utils.html import format_html
from django.urls import reverse

# Register your models here.
from .models import *
from parasight import tasks


class Zone_Admin(admin.ModelAdmin):
    search_fields = [
        'id',
        'network',
    ]
    list_display = [
        'id',
        'name',
        'sites_count',
    ]
    actions = [
        'runDiscoveryNetworks',
        #'runFastScanNetworks',
        #'runNormalScanNetworks',
        #'runFullScanNetworks',
        'runFastScanHosts',
        'runNormalScanHosts',
        'runFullScanHosts',
    ]


    def get_queryset(self, request):
        qs = super().get_queryset(request)\
            .annotate(
                sites_count=Count('sites', filter=Q(sites__enabled=True), distinct=True),
        )

        return qs


    def sites_count(self, obj):
        return obj.sites_count
    sites_count.admin_order_field = 'sites_count'
    sites_count.short_description = 'Scan Sites'


    def runDiscoveryNetworks(self, request, qs):
        task_list = list()
        for zone in qs:
            for network in zone.getNetworks():
                network.populateHosts()

                for site in network.getSites():
                    logger.info(
                        'Create network discover task for %s at site %s on queue %s',
                        network.network,
                        site.name,
                        site.queue.name
                    )
                    t = tasks.DiscoverNetworkAtSite().si(network.id, site.id)
                    t.apply_async(queue=site.queue.name)

                    task_list.append(t)

        self.message_user(request, 'Discovery initiated for {0:d} zones ({1:d} tasks)'.format(qs.count(), len(task_list)))
    runDiscoveryNetworks.short_description = 'Run Network Discovery'


    def _runScanHosts(self, request, qs, scan_class_str, message):
        task_list = list()
        for zone in qs:
            for network in zone.getNetworks():
                network.populateHosts()

                for host in network.getHostsOnline():

                    for site in host.getSites():
                        logger.info(
                            'Create scan task for %s at site %s on queue %s',
                            host.address,
                            site.name,
                            site.queue.name
                        )

                        task_class = getattr(tasks, scan_class_str)

                        t = task_class().si(host.id, site.id)
                        t.apply_async(queue=site.queue.name)

                        task_list.append(t)

        self.message_user(request, '{0:s} initiated for {1:d} zones ({2:d} tasks)'.format(message, qs.count(), len(task_list)))


    def runFastScanHosts(self, request, qs):
        _scan_class_str = 'FastScanHostAtSite'
        _message = 'Host Fast Scan'

        self._runScanHosts(request, qs, _scan_class_str, _message)
    runFastScanHosts.short_description = 'Hosts Fast Scan'

    def runNormalScanHosts(self, request, qs):
        _scan_class_str = 'NormalScanHostAtSite'
        _message = 'Host Normal Scan'

        self._runScanHosts(request, qs, _scan_class_str, _message)
    runNormalScanHosts.short_description = 'Hosts Normal Scan'

    def runFullScanHosts(self, request, qs):
        _scan_class_str = 'FullScanHostAtSite'
        _message = 'Host Full Scan'

        self._runScanHosts(request, qs, _scan_class_str, _message)
    runFullScanHosts.short_description = 'Hosts Full Scan'




admin.site.register(Zone, Zone_Admin)


class Site_Admin(admin.ModelAdmin):
    search_fields = [
        'id',
        'network',
    ]
    list_display = [
        'id',
        'name',
        'get_queue_name',
        'enabled',
    ]

    def get_queue_name(self, obj):
        return obj.queue.name
    get_queue_name.admin_order_field = 'queue'
    get_queue_name.short_description = 'Queue'


admin.site.register(Site, Site_Admin)


admin.site.register(SiteQueue)
admin.site.register(SiteScanSource)


class Network_Admin(admin.ModelAdmin):
    filter_horizontal = [
        'networkScans',
        'networkDiscoveries',
        'hosts',
        'metadata',
    ]
    search_fields = [
        'id',
        'network',
    ]
    list_display = [
        'id',
        'network',
        'hosts_count',
        'get_zone_name',
        'sites_count',
        'networkScans_count',
        'networkDiscoveries_count',
        'enabled',
    ]
    actions = [
        'runDiscoveryNetworks',
        'runFastScanNetworks',
        'runNormalScanNetworks',
        'runFullScanNetworks',
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)\
            .annotate(
                hosts_count=Count('hosts', distinct=True),
                networkScans_count=Count('networkScans', distinct=True),
                networkDiscoveries_count=Count('networkDiscoveries', distinct=True),
                sites_count=Count('zone__sites', filter=Q(zone__sites__enabled=True), distinct=True),
        )

        return qs

    def runDiscoveryNetworks(self, request, qs):
        task_list = list()
        for network in qs:
            network.populateHosts()

            for site in network.getSites():
                logger.info(
                    'Create network discover task for %s at site %s on queue %s',
                    network.network,
                    site.name,
                    site.queue.name
                )
                t = tasks.DiscoverNetworkAtSite().si(network.id, site.id)
                t.apply_async(queue=site.queue.name)

                task_list.append(t)

        self.message_user(request, 'Discovery initiated for {0:d} networks ({1:d} tasks)'.format(qs.count(), len(task_list)))
    runDiscoveryNetworks.short_description = 'Run Network Discovery'

    def _runScanNetworks(self, request, qs, scan_class_str, message):
        task_list = list()
        for network in qs:
            network.populateHosts()

            for site in network.getSites():
                logger.info(
                    'Create scan task for %s at site %s on queue %s',
                    network.network,
                    site.name,
                    site.queue.name
                )

                task_class = getattr(tasks, scan_class_str)

                t = task_class().si(network.id, site.id)
                t.apply_async(queue=site.queue.name)

                task_list.append(t)

        self.message_user(request, '{0:s} initiated for {1:d} networks ({2:d} tasks)'.format(message, qs.count(), len(task_list)))


    def runFastScanNetworks(self, request, qs):
        _scan_class_str = 'FastScanNetworkAtSite'
        _message = 'Fast Scan'

        self._runScanNetworks(request, qs, _scan_class_str, _message)
    runFastScanNetworks.short_description = 'Fast Scan'

    def runNormalScanNetworks(self, request, qs):
        _scan_class_str = 'NormalScanNetworkAtSite'
        _message = 'Normal Scan'

        self._runScanNetworks(request, qs, _scan_class_str, _message)
    runNormalScanNetworks.short_description = 'Normal Scan'

    def runFullScanNetworks(self, request, qs):
        _scan_class_str = 'FullScanNetworkAtSite'
        _message = 'Full Scan'

        self._runScanNetworks(request, qs, _scan_class_str, _message)
    runFullScanNetworks.short_description = 'Full Scan'

    def sites_count(self, obj):
        return obj.sites_count
    sites_count.admin_order_field = 'sites_count'
    sites_count.short_description = 'Scan Sites'

    def hosts_count(self, obj):
        return obj.hosts_count
    hosts_count.admin_order_field = 'hosts_count'
    hosts_count.short_description = 'Host Count'

    def networkScans_count(self, obj):
        return obj.networkScans_count
    networkScans_count.admin_order_field = 'networkScans_count'
    networkScans_count.short_description = 'Scan Count'

    def networkDiscoveries_count(self, obj):
        return obj.networkDiscoveries_count
    networkDiscoveries_count.admin_order_field = 'networkDiscoveries_count'
    networkDiscoveries_count.short_description = 'Discovery Count'

    def get_readonly_fields(self, request, obj=None):
        if obj:  # editing an existing object
            return self.readonly_fields + ('network',)
        return self.readonly_fields

    def get_zone_name(self, obj):
        return obj.zone.name
    get_zone_name.admin_order_field = 'zone'
    get_zone_name.short_description = 'Zone'


admin.site.register(Network, Network_Admin)


admin.site.register(NetworkMetadata)


class Host_Admin(admin.ModelAdmin):
    filter_horizontal = [
        'hostScans',
        'hostDiscoveries',
    ]
    search_fields = [
        'id',
        'address',
    ]
    list_display = [
        'id',
        'address',
        'hostScans_count',
        'hostDiscoveries_count',
        'online',
        'firewallState',
        'forceOnline',
        'enabled',
        'open_ports',
        'closed_ports',
    ]
    list_filter = [
        'online',
    ]
    actions = [
        'runDiscoveryHosts',
        'runFastScanHosts',
        'runNormalScanHosts',
        'runFullScanHosts',
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)\
            .annotate(
                hostScans_count=Count('hostScans', distinct=True),
                hostDiscoveries_count=Count('hostDiscoveries', distinct=True),
        )

        return qs

    def runDiscoveryHosts(self, request, qs):
        task_list = list()
        for host in qs:
            for site in host.getSites():
                logger.info(
                    'Create host discover task for %s at site %s on queue %s',
                    host.address,
                    site.name,
                    site.queue.name
                )
                t = tasks.DiscoverHostAtSite().si(host.id, site.id)
                t.apply_async(queue=site.queue.name)

                task_list.append(t)

        self.message_user(request, 'Discovery initiated for {0:d} hosts ({1:d} tasks)'.format(qs.count(), len(task_list)))
    runDiscoveryHosts.short_description = 'Run Host Discovery'

    def _runScanHosts(self, request, qs, scan_class_str, message):
        task_list = list()
        for host in qs:
            for site in host.getSites():
                logger.info(
                    'Create scan task for %s at site %s on queue %s',
                    host.address,
                    site.name,
                    site.queue.name
                )

                task_class = getattr(tasks, scan_class_str)

                t = task_class().si(host.id, site.id)
                t.apply_async(queue=site.queue.name)

                task_list.append(t)

        self.message_user(request, '{0:s} initiated for {1:d} hosts ({2:d} tasks)'.format(message, qs.count(), len(task_list)))


    def runFastScanHosts(self, request, qs):
        _scan_class_str = 'FastScanHostAtSite'
        _message = 'Host Fast Scan'

        self._runScanHosts(request, qs, _scan_class_str, _message)
    runFastScanHosts.short_description = 'Hosts Fast Scan'

    def runNormalScanHosts(self, request, qs):
        _scan_class_str = 'NormalScanHostAtSite'
        _message = 'Host Normal Scan'

        self._runScanHosts(request, qs, _scan_class_str, _message)
    runNormalScanHosts.short_description = 'Hosts Normal Scan'

    def runFullScanHosts(self, request, qs):
        _scan_class_str = 'FullScanHostAtSite'
        _message = 'Host Full Scan'

        self._runScanHosts(request, qs, _scan_class_str, _message)
    runFullScanHosts.short_description = 'Hosts Full Scan'

    def firewallState(self, obj):
        return obj.getFirewallState()
    firewallState.short_description = 'Firewall'

    def hostScans_count(self, obj):
        return obj.hostScans_count
    hostScans_count.admin_order_field = 'hostScans_count'
    hostScans_count.short_description = 'Scan Count'

    def hostDiscoveries_count(self, obj):
        return obj.hostDiscoveries_count
    hostDiscoveries_count.admin_order_field = 'hostDiscoveries_count'
    hostDiscoveries_count.short_description = 'Discovery Count'

    def get_readonly_fields(self, request, obj=None):
        if obj:  # editing an existing object
            return self.readonly_fields + ('address',)
        return self.readonly_fields

    def open_ports(self, obj):
        open_ports = obj.getOpenPortsLatestScans()

        port_set = set()
        for port in open_ports.order_by('port'):
            port_set.add(port.port_proto)

        html_out = '<br/>'.join(port_set)

        return mark_safe(html_out)
    open_ports.short_description = 'Open Ports'

    def closed_ports(self, obj):
        closed_ports = obj.getClosedPortsLatestScans()

        port_set = set()
        for port in closed_ports.order_by('port'):
            port_set.add(port.port_proto)

        html_out = '<br/>'.join(port_set)

        return mark_safe(html_out)
    closed_ports.short_description = 'Refused Ports'


admin.site.register(Host, Host_Admin)


class NetworkScan_Admin(admin.ModelAdmin):
    filter_horizontal = [
        'hostScans',
    ]
    search_fields = [
        'id',
        'network__network',
    ]
    list_display = [
        'id',
        'scanType',
        'get_network_network',
        'get_network_zone_name',
        'get_site_name',
        'scanDate',
        'scantime',
        'complete',
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)\
            .annotate(
                scantime=F('finishedtime') - F('starttime'),
        )

        return qs

    def scantime(self, obj):
        return obj.scantime
    scantime.admin_order_field = 'scantime'
    scantime.short_description = 'Scan Time'

    def get_site_name(self, obj):
        return obj.site.name
    get_site_name.admin_order_field = 'site'
    get_site_name.short_description = 'Site Name'

    def get_network_network(self, obj):
        return obj.network_set.first().network
    get_network_network.admin_order_field = 'network__network'
    get_network_network.short_description = 'Network'

    def get_network_zone_name(self, obj):
        return obj.network_set.first().zone.name
    get_network_zone_name.admin_order_field = 'network__zone'
    get_network_zone_name.short_description = 'Zone'


admin.site.register(NetworkScan, NetworkScan_Admin)


class HostScan_Admin(admin.ModelAdmin):
    filter_horizontal = [
        'scanPorts',
    ]
    search_fields = [
        'id',
        'host__address',
    ]
    list_display = [
        'id',
        'scanType',
        'get_host_address',
        'get_site_name',
        'scanDate',
        'scantime',
        'complete',
    ]
    actions = [
        'generateHostScanReport',
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)\
            .annotate(
                scantime=F('endtime') - F('starttime'),
        )

        return qs

    def scantime(self, obj):
        return obj.scantime
    scantime.admin_order_field = 'scantime'
    scantime.short_description = 'Scan Time'

    def get_site_name(self, obj):
        return obj.site.name
    get_site_name.admin_order_field = 'site'
    get_site_name.short_description = 'Site Name'

    def get_host_address(self, obj):
        return obj.host_set.first().address
    get_host_address.admin_order_field = 'host__address'
    get_host_address.short_description = 'Host'


    def generateHostScanReport(self, request, qs):
        for scan in qs:
            scan.generateHostScanReport()

        self.message_user(request, 'Generated {0:d} host scan reports'.format(qs.count()))
    generateHostScanReport.short_description = 'Generate Scan Report'


admin.site.register(HostScan, HostScan_Admin)


class NetworkDiscovery_Admin(admin.ModelAdmin):
    filter_horizontal = [
        'hostDiscoveries',
    ]
    search_fields = [
        'id',
        'network__network',
    ]
    list_display = [
        'id',
        'get_network_network',
        'get_network_zone_name',
        'get_site_name',
        'scanDate',
        'scantime',
        'complete',
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)\
            .annotate(
                scantime=F('finishedtime') - F('starttime'),
        )

        return qs

    def scantime(self, obj):
        return obj.scantime
    scantime.admin_order_field = 'scantime'
    scantime.short_description = 'Scan Time'

    def get_site_name(self, obj):
        return obj.site.name
    get_site_name.admin_order_field = 'site'
    get_site_name.short_description = 'Site Name'

    def get_network_network(self, obj):
        return obj.network_set.first().network
    get_network_network.admin_order_field = 'network__network'
    get_network_network.short_description = 'Network'

    def get_network_zone_name(self, obj):
        return obj.network_set.first().zone.name
    get_network_zone_name.admin_order_field = 'network__zone'
    get_network_zone_name.short_description = 'Zone'


admin.site.register(NetworkDiscovery, NetworkDiscovery_Admin)


class HostDiscovery_Admin(admin.ModelAdmin):
    search_fields = [
        'id',
    ]
    list_display = [
        'id',
        'get_host_address',
        'get_network_network',
        'get_host_zone_name',
        'get_site_name',
        'scanDate',
        'complete',
    ]

    def get_site_name(self, obj):
        return obj.site.name
    get_site_name.admin_order_field = 'site'
    get_site_name.short_description = 'Site Name'

    def get_host_address(self, obj):
        return obj.host_set.first().address
    get_host_address.admin_order_field = 'host__address'
    get_host_address.short_description = 'Host'

    def get_network_network(self, obj):
        return obj.host_set.first().getNetwork().network
    get_network_network.admin_order_field = 'host__network__network'
    get_network_network.short_description = 'Network'

    def get_host_zone_name(self, obj):
        return obj.host_set.first().getZone().name
    get_host_zone_name.admin_order_field = 'host__network__zone'
    get_host_zone_name.short_description = 'Zone'


admin.site.register(HostDiscovery, HostDiscovery_Admin)


class ScanPort_Admin(admin.ModelAdmin):
    filter_horizontal = [
        'serviceInfo',
    ]
    search_fields = [
        'id',
        'port',
    ]
    list_display = [
        'id',
        'port',
        'protocol',
        'state',
        'get_host_address',
        'get_hostScan',
        'get_serviceInfo_name',
        'get_serviceInfo_product',
        'get_serviceInfo_version',
    ]
    list_filter = [
        'state',
    ]


    def get_host_address(self, obj):
        host = obj.getHost()

        if not host:
            return ''

        url = reverse('admin:parasight_host_change', args=[host.pk])

        return format_html('<a href="{0:s}">{1:s}</a>'.format(url, host.address))
    get_host_address.admin_order_field = 'hostScan__host'
    get_host_address.short_description = 'Host'


    def get_hostScan(self, obj):
        hostScan = obj.getHostScan()

        if not hostScan:
            return ''

        url = reverse('admin:parasight_hostscan_change', args=[hostScan.pk])

        return format_html('<a href="{0:s}">{1:d}</a>'.format(url, hostScan.id))
    get_hostScan.admin_order_field = 'hostScan'
    get_hostScan.short_description = 'Host Scan'


    def get_serviceInfo_name(self, obj):
        serviceInfo = obj.getServiceInfo('name')

        if not serviceInfo:
            return ''

        return serviceInfo.value
    get_serviceInfo_name.short_description = 'Name'


    def get_serviceInfo_product(self, obj):
        serviceInfo = obj.getServiceInfo('product')

        if not serviceInfo:
            return ''

        return serviceInfo.value
    get_serviceInfo_product.short_description = 'Product'


    def get_serviceInfo_version(self, obj):
        serviceInfo = obj.getServiceInfo('version')

        if not serviceInfo:
            return ''

        return serviceInfo.value
    get_serviceInfo_version.short_description = 'Version'


admin.site.register(ScanPort, ScanPort_Admin)


admin.site.register(ScanPortServiceInfo)
