import os
import socket
import ipaddress
import re
import random
import tempfile
import subprocess
import io
from datetime import datetime
from pathlib import Path
import logging

import xml.etree.ElementTree as ET

from openpyxl import Workbook

from django.db import models
from django.utils import timezone as django_timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.db.models.functions import Concat
from django.db.models import Q
from django.db.models import F
from django.db.models import Value
from django.db.models import CharField
from django.core.files.base import ContentFile

logger = logging.getLogger(__name__)



# Do not record these service keys
FILTER_SERVICE_KEYS = [
    'servicefp',
]


# Create your models here.

class Zone(models.Model):
    name           = models.CharField(max_length=50, unique=True)
    description    = models.TextField()
    sites          = models.ManyToManyField('Site', blank=True)

    class Meta:
        app_label = 'parasight'


    def __str__(self):
        return '{0:s}'.format(self.name)


    def getNetworks(self):
        return self.network_set.filter(enabled=True)



class Site(models.Model):
    name           = models.CharField(max_length=50, unique=True)
    description    = models.TextField()
    queue          = models.ForeignKey('SiteQueue', on_delete=models.PROTECT)
    sources        = models.ManyToManyField('SiteScanSource')
    enabled        = models.BooleanField(default=True)

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:s}'.format(self.name)

    def getQueue(self):
        return self.queue

    def getSource(self):
        source_list = list()

        try:
            self.sources.get(network='any')
            logger.info('Using any source address for scan')
            return 'any'
        except SiteScanSource.DoesNotExist:
            pass


        sources_enabled = self.sources.filter(enabled=True)

        for source in sources_enabled:
            source_list.extend(list(ipaddress.ip_network(source.network)))


        random.shuffle(source_list)

        source_ip = str(source_list[0])
        logger.info('Found source address for scan: %s', str(source_ip))

        return source_ip



class SiteQueue(models.Model):
    name           = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return '{0:s}'.format(self.name)

    class Meta:
        app_label = 'parasight'


def SiteScanSource_network_cidr_validator(network_str):
    if network_str == 'any':
        return

    m = re.search(r'\/', network_str)
    if not m:
        raise ValidationError(
            _('%(network)s is not a valid network/cidr'),
            params={'network': network_str},
        )


    try:
        ipaddress.ip_network(network_str)
    except ValueError as e:
        raise ValidationError(
            _('%(network)s is not a valid network/cidr: %(error)s'),
            params={'network': network_str, 'error': str(e)},
        )





class SiteScanSource(models.Model):
    network        = models.CharField(max_length=40, validators=[SiteScanSource_network_cidr_validator])
    enabled        = models.BooleanField(default=True)

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:s}'.format(self.network)


def Network_network_cidr_validator(network_str):
    m = re.search(r'\/', network_str)
    if not m:
        raise ValidationError(
            _('%(network)s is not a valid network/cidr'),
            params={'network': network_str},
        )


    try:
        network = ipaddress.ip_network(network_str)
    except ValueError as e:
        raise ValidationError(
            _('%(network)s is not a valid network/cidr: %(error)s'),
            params={'network': network_str, 'error': str(e)},
        )


    if network.version == 6:
        if network.prefixlen < 118:
            raise ValidationError(
                _('%(network)s is too large.  Please restrict to 1024 addresses.'),
                params={'network': network_str, },
            )
    else:
        if network.prefixlen < 22:
            raise ValidationError(
                _('%(network)s is too large.  Please restrict to 1024 addresses.'),
                params={'network': network_str, },
            )


class Network(models.Model):
    network        = models.CharField(max_length=40, validators=[Network_network_cidr_validator])
    description    = models.TextField()
    enabled        = models.BooleanField(default=True)
    zone           = models.ForeignKey('Zone', on_delete=models.PROTECT)
    networkScans   = models.ManyToManyField('NetworkScan', blank=True)
    networkDiscoveries   = models.ManyToManyField('NetworkDiscovery', blank=True)
    hosts          = models.ManyToManyField('Host', blank=True)
    staticRouted   = models.BooleanField(default=False)
    metadata       = models.ManyToManyField('NetworkMetadata', blank=True)

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:s} - {1:s}'.format(self.network, self.zone.name)


    def getAddresses(self):
        return ipaddress.ip_network(self.network)

    def getZone(self):
        return self.zone

    def getSites(self):
        zone = self.getZone()

        return zone.sites.filter(enabled=True)

    def getHostsOnline(self):
        hosts_online = self.hosts.filter(enabled=True)\
            .filter(
                Q(online=True)
                | Q(forceOnline=True)  # noqa: W503
        )

        return hosts_online

    def populateHosts(self):
        network = ipaddress.ip_network(self.network)

        if network.version == 6:
            logger.info('Network is IPv6')
            if network.prefixlen == 128:
                ip_gen = network
            elif network.prefixlen < 118:
                #limit hosts to 1024
                subnets_gen = network.subnet(new_prefix=118)

                # memory optimized approach to getting a subset of addresses
                sub_network = next(subnets_gen)

                if not self.staticRouted:
                    ip_gen = sub_network.hosts()
                else:
                    ip_gen = sub_network  # include network IP

            else:
                if not self.staticRouted:
                    ip_gen = network.hosts()
                else:
                    ip_gen = network  # include network IP

        else:
            logger.info('Network is IPv4')
            if network.prefixlen == 32:
                ip_gen = network
            elif network.prefixlen < 22:
                #limit hosts to 1024
                subnets_gen = network.subnet(new_prefix=22)

                # memory optimized approach to getting a subset of addresses
                sub_network = next(subnets_gen)

                if not self.staticRouted:
                    ip_gen = sub_network.hosts()
                else:
                    ip_gen = sub_network  # include network IP and broadcast
            else:
                if not self.staticRouted:
                    ip_gen = network.hosts()
                else:
                    ip_gen = network  # include network IP and broadcast


        for ip in ip_gen:
            ip_str = str(ip)

            try:
                self.hosts.get(address=ip_str)
                #logger.info('Host for %s exists', ip_str)
            except Host.DoesNotExist:
                logger.info('Creating host for %s', ip_str)
                new_host = Host(
                    address=ip_str,
                )
                new_host.save()

                self.hosts.add(new_host)


    def runDiscoveryAtSite(self, site_id):
        site = Site.objects.get(id=site_id)

        logger.info('Starting network discovery for %s at site %s', self.network, site.name)

        # Get a new tempfile name
        xml_fh = tempfile.NamedTemporaryFile(delete=False, prefix='parasight_net_', suffix='.xml')
        xml_filename = xml_fh.name
        xml_fh.close()

        logger.info('Discovery temporary file: %s', xml_filename)


        source_ip = site.getSource()

        if source_ip == 'any':
            nmap_source = ''
        else:
            nmap_source = '-S {0:s}'.format(str(source_ip))

        cmd = '/usr/local/bin/nmap -sn -PE -PP -PS22,80,389,443,445,636,1352,1414,1434,1521,2222,3306,3389,5432,5672,5984,8080,8443,9080,9043,9060,9200,9443,27017,50000 -n {0:s} -oX {1:s} {2:s}'.format(nmap_source, xml_filename, self.network)
        logger.info('Command: %s', cmd)


        logger.warn('Running network discovery with source IP: %s', str(source_ip))
        nmap = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_stdout, nmap_stderr = nmap.communicate()

        if nmap.returncode > 0:
            raise Exception('Problem discovering network {0:d}: {1:s}'.format(self.id, nmap_stderr.decode()))



        f_xml = open(xml_filename, 'r')
        xml_str = f_xml.read()
        f_xml.close()

        if not settings.DEBUG:
            # delete in prod
            os.unlink(xml_filename)


        #parse the nmap output
        #xml_tree = ET.parse(xml_filename)
        #xml_root = xml_tree.getroot()
        xml_root = ET.fromstring(xml_str)

        nmap_version = xml_root.attrib['version']
        starttime = int(xml_root.attrib['start'])

        xml_runstats_branch = xml_root.find('./runstats')
        xml_runstats_finished_branch = xml_runstats_branch.find('./finished')
        finishedtime = int(xml_runstats_finished_branch.attrib['time'])

        xml_runstats_hosts_branch = xml_runstats_branch.find('./hosts')
        hosts_up    = int(xml_runstats_hosts_branch.attrib['up'])
        hosts_total = int(xml_runstats_hosts_branch.attrib['total'])


        scanHost = socket.gethostname()

        network_discovery = NetworkDiscovery(
            site=site,
            sourceAddress=source_ip,
            scanHost=scanHost,
            nmap_version=nmap_version,
            starttime=starttime,
            finishedtime=finishedtime,
            hosts_up=hosts_up,
            hosts_total=hosts_total,
            xmlText=xml_str,
        )
        network_discovery.save()

        self.networkDiscoveries.add(network_discovery)


        xml_host_branch = xml_root.findall('./host')


        for xml_host in xml_host_branch:
            xml_host_address_branch = xml_host.find('./address')
            addr = xml_host_address_branch.attrib['addr']

            logger.info('Found host with address: %s', addr)
            host = self.hosts.get(address=addr)  # Lookup host

            host_discovery = HostDiscovery(
                site=site,
                sourceAddress=source_ip,
                nmap_version=nmap_version,
            )
            host_discovery.save()

            # Associate discovery to NetworkDiscovery and Host
            network_discovery.hostDiscoveries.add(host_discovery)
            host.hostDiscoveries.add(host_discovery)

            host.parseNmapDiscovery(xml_host)

            host_discovery.complete = True
            host_discovery.save()


        network_discovery.complete = True
        network_discovery.save()


    def fastScan(self, site_id, timing=4):
        nmap_command = '/usr/local/bin/nmap -T{0:d} -PE -PP -PS22,80,389,443,445,636,1352,1414,1434,1521,2222,3306,3389,5432,5672,5984,8080,8443,9080,9043,9060,9200,9443,27017,50000 -sV -F {1:s} -oX {2:s} {3:s}'
        scanType = 'fast'

        self._runScan(scanType, nmap_command, site_id, timing)


    def normalScan(self, site_id, timing=3):
        nmap_command = '/usr/local/bin/nmap -T{0:d} -PE -PP -PS22,80,389,443,445,636,1352,1414,1434,1521,2222,3306,3389,5432,5672,5984,8080,8443,9080,9043,9060,9200,9443,27017,50000 -T4 -sV {1:s} -oX {2:s} {3:s}'
        scanType = 'normal'

        self._runScan(scanType, nmap_command, site_id, timing)


    def fullScan(self, site_id, timing=3):
        nmap_command = '/usr/local/bin/nmap -T{0:d} -PE -PP -PS22,80,389,443,445,636,1352,1414,1434,1521,2222,3306,3389,5432,5672,5984,8080,8443,9080,9043,9060,9200,9443,27017,50000 -sV -p1-65535 {1:s} -oX {2:s} {3:s}'
        scanType = 'full'

        self._runScan(scanType, nmap_command, site_id, timing)


    def _runScan(self, scanType, nmap_command, site_id, timing):
        site = Site.objects.get(id=site_id)

        logger.info('Starting %s network scan for %s at site %s', scanType, self.network, site.name)

        # Get a new tempfile name
        xml_fh = tempfile.NamedTemporaryFile(delete=False, prefix='parasight_net_', suffix='.xml')
        xml_filename = xml_fh.name
        xml_fh.close()

        logger.info('Scan temporary file: %s', xml_filename)


        source_ip = site.getSource()

        if source_ip == 'any':
            nmap_source = ''
        else:
            nmap_source = '-S {0:s}'.format(str(source_ip))

        cmd = nmap_command.format(timing, nmap_source, xml_filename, self.network)
        logger.info('Command: %s', cmd)


        logger.warn('Running network scan with source IP: %s', source_ip)
        nmap = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_stdout, nmap_stderr = nmap.communicate()

        if nmap.returncode > 0:
            raise Exception('Problem scanning network {0:d}: {1:s}'.format(self.id, str(nmap_stderr)))


        f_xml = open(xml_filename, 'r')
        xml_str = f_xml.read()
        f_xml.close()

        if not settings.DEBUG:
            # delete in prod
            os.unlink(xml_filename)


        #parse the nmap output
        #xml_tree = ET.parse(xml_filename)
        #xml_root = xml_tree.getroot()
        xml_root = ET.fromstring(xml_str)

        nmap_version = xml_root.attrib['version']
        starttime = int(xml_root.attrib['start'])

        xml_root_scaninfo_branch = xml_root.find('./scaninfo')
        numservices = int(xml_root_scaninfo_branch.attrib['numservices'])

        xml_host_branch = xml_root.findall('./host')

        xml_runstats_branch = xml_root.find('./runstats')
        xml_runstats_finished_branch = xml_runstats_branch.find('./finished')
        finishedtime = int(xml_runstats_finished_branch.attrib['time'])

        xml_runstats_hosts_branch = xml_runstats_branch.find('./hosts')
        hosts_up    = int(xml_runstats_hosts_branch.attrib['up'])
        hosts_total = int(xml_runstats_hosts_branch.attrib['total'])


        scanHost = socket.gethostname()

        network_scan = NetworkScan(
            site=site,
            sourceAddress=source_ip,
            scanHost=scanHost,
            scanType=scanType,
            nmap_version=nmap_version,
            numservices=numservices,
            starttime=starttime,
            finishedtime=finishedtime,
            hosts_up=hosts_up,
            hosts_total=hosts_total,
            xmlText=xml_str,
        )
        network_scan.save()

        self.networkScans.add(network_scan)


        for xml_host in xml_host_branch:
            xml_host_address_branch = xml_host.find('./address')
            addr = xml_host_address_branch.attrib['addr']

            logger.info('Found scan for address: %s', addr)
            host = self.hosts.get(address=addr)  # Lookup host
            host.save()

            xml_host_status_branch = xml_host.find('./status')
            status_state = xml_host_status_branch.attrib['state']
            status_reason = xml_host_status_branch.attrib['reason']


            # Mark host as up
            if status_state == 'up':
                if status_reason != 'user-set':  # user-set means scan was forced
                    logger.info('Host detected as online')
                    host.online = True
                    host.save()


            host_scan = HostScan(
                site=site,
                sourceAddress=source_ip,
                scanType=scanType,
                nmap_version=nmap_version,
                numservices=numservices,
            )
            host_scan.save()


            # Associate scan to NetworkScan and Host
            network_scan.hostScans.add(host_scan)
            host.hostScans.add(host_scan)

            host_scan.parseNmapScan(xml_host)

            host_scan.complete = True
            host_scan.save()


        network_scan.complete = True
        network_scan.save()


class NetworkMetadata(models.Model):
    key            = models.CharField(max_length=10)
    value          = models.TextField()

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:s}'.format(self.key)



class Host(models.Model):
    address        = models.CharField(max_length=40)
    online         = models.BooleanField(default=False)
    forceOnline    = models.BooleanField(default=False)
    enabled        = models.BooleanField(default=True)
    hostScans      = models.ManyToManyField('HostScan', blank=True)
    hostDiscoveries   = models.ManyToManyField('HostDiscovery', blank=True)

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:s}'.format(self.address)


    def getNetwork(self):
        return self.network_set.first()


    def getZone(self):
        network = self.getNetwork()

        return network.zone


    def getSites(self):
        zone = self.getZone()

        return zone.sites.filter(enabled=True)


    def getFirewallActive(self):
        scans = self.getLatestScans()

        if not scans:
            # no scans found
            return None

        if not self.online and not self.forceOnline:
            # host not online
            return None

        scan = scans.first()

        if scan.refusedports > 50:
            return False

        if scan.filteredports > 50:
            return True

        return None


    def getFirewallState(self):
        active = self.getFirewallActive()

        if active is True:
            return 'Active'

        if active is False:
            return 'No firewall'

        return ''


    def getLatestScans(self):
        sites = self.getSites()

        scan_ids = list()
        for site in sites:
            latest_site_host_scan = self.hostScans.filter(site=site).order_by('-scanDate').first()

            if not latest_site_host_scan:
                continue

            scan_ids.append(latest_site_host_scan.id)


        return self.hostScans.filter(id__in=scan_ids)


    def getPortsLatestScans(self, state='open'):
        latest_scans = self.getLatestScans()

        latest_scans = ScanPort.objects\
            .filter(state=state)\
            .filter(id__in=latest_scans.values_list('scanPorts__id', flat=True))

        latest_scans_annotated = latest_scans.annotate(
            port_proto=Concat(
                F('port'),
                Value('/'),
                F('protocol'),
                output_field=CharField(),
            )
        )

        return latest_scans_annotated


    def getOpenPortsLatestScans(self):
        return self.getPortsLatestScans(state='open')


    def getClosedPortsLatestScans(self):
        return self.getPortsLatestScans(state='closed')


    def fastScan(self, site_id, timing=4):
        nmap_command = '/usr/local/bin/nmap -T{0:d} -Pn -sV -F {1:s} -oX {2:s} {3:s}'
        scanType = 'fast'

        self._runScan(scanType, nmap_command, site_id, timing)


    def normalScan(self, site_id, timing=3):
        nmap_command = '/usr/local/bin/nmap -T{0:d} -Pn -sV {1:s} -oX {2:s} {3:s}'
        scanType = 'normal'

        self._runScan(scanType, nmap_command, site_id, timing)


    def fullScan(self, site_id, timing=3):
        nmap_command = '/usr/local/bin/nmap -T{0:d} -Pn -sV -p1-65535 {1:s} -oX {2:s} {3:s}'
        scanType = 'full'

        self._runScan(scanType, nmap_command, site_id, timing)



    def _runScan(self, scanType, nmap_command, site_id, timing):
        site = Site.objects.get(id=site_id)

        logger.info('Starting %s scan for %s at site %s', scanType, self.address, site.name)

        # Get a new tempfile name
        xml_fh = tempfile.NamedTemporaryFile(delete=False, prefix='parasight_', suffix='.xml')
        xml_filename = xml_fh.name
        xml_fh.close()

        logger.info('Scan temporary file: %s', xml_filename)


        source_ip = site.getSource()

        if source_ip == 'any':
            nmap_source = ''
        else:
            nmap_source = '-S {0:s}'.format(str(source_ip))

        cmd = nmap_command.format(timing, nmap_source, xml_filename, self.address)
        logger.info('Command: %s', cmd)


        logger.warn('Running scan with source IP: %s', source_ip)
        nmap = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_stdout, nmap_stderr = nmap.communicate()

        if nmap.returncode > 0:
            raise Exception('Problem scanning host {0:d}: {1:s}'.format(self.id, str(nmap_stderr)))


        f_xml = open(xml_filename, 'r')
        xml_str = f_xml.read()
        f_xml.close()

        if not settings.DEBUG:
            # delete in prod
            os.unlink(xml_filename)


        #parse the nmap output
        #xml_tree = ET.parse(xml_filename)
        #xml_root = xml_tree.getroot()
        xml_root = ET.fromstring(xml_str)

        nmap_version = xml_root.attrib['version']

        xml_root_scaninfo_branch = xml_root.find('./scaninfo')
        numservices = int(xml_root_scaninfo_branch.attrib['numservices'])

        xml_host_branch = xml_root.findall('./host')
        xml_host_0 = xml_host_branch[0]


        scanHost = socket.gethostname()

        scan = HostScan(
            site=site,
            sourceAddress=source_ip,
            scanHost=scanHost,
            scanType=scanType,
            nmap_version=nmap_version,
            numservices=numservices,
            xmlText=xml_str,
        )
        scan.save()

        self.hostScans.add(scan)


        scan.parseNmapScan(xml_host_0)



    def runDiscoveryAtSite(self, site_id):
        site = Site.objects.get(id=site_id)

        logger.info('Starting discovery for %s at site %s', self.address, site.name)

        # Get a new tempfile name
        xml_fh = tempfile.NamedTemporaryFile(delete=False, prefix='parasight_', suffix='.xml')
        xml_filename = xml_fh.name
        xml_fh.close()

        logger.info('Discovery temporary file: %s', xml_filename)


        source_ip = site.getSource()

        if source_ip == 'any':
            nmap_source = ''
        else:
            nmap_source = '-S {0:s}'.format(str(source_ip))

        cmd = '/usr/local/bin/nmap -sn -PE -PP -PS22,80,389,443,445,636,1352,1414,1434,1521,2222,3306,3389,5432,5672,5984,8080,8443,9080,9043,9060,9200,9443,27017,50000 -n {0:s} -oX {1:s} {2:s}'.format(nmap_source, xml_filename, self.address)
        logger.info('Command: %s', cmd)


        logger.warn('Running discovery with source IP: %s', source_ip)
        nmap = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_stdout, nmap_stderr = nmap.communicate()

        if nmap.returncode > 0:
            raise Exception('Problem discovering host {0:d}: {1:s}'.format(self.id, nmap_stderr))


        f_xml = open(xml_filename, 'r')
        xml_str = f_xml.read()
        f_xml.close()

        if not settings.DEBUG:
            # delete in prod
            os.unlink(xml_filename)


        #parse the nmap output
        #xml_tree = ET.parse(xml_filename)
        #xml_root = xml_tree.getroot()
        xml_root = ET.fromstring(xml_str)

        xml_host_branch = xml_root.findall('./host')
        nmap_version = xml_root.attrib['version']


        scanHost = socket.gethostname()

        # Create Host Discovery object before processing results
        host_discovery = HostDiscovery(
            site=site,
            sourceAddress=source_ip,
            scanHost=scanHost,
            nmap_version=nmap_version,
            xmlText=xml_str,
            complete=True,
        )
        host_discovery.save()

        self.hostDiscoveries.add(host_discovery)


        try:
            xml_host_0 = xml_host_branch[0]
        except IndexError:
            logger.info('Host is not online')
            return


        self.parseNmapDiscovery(xml_host_0)



    def parseNmapDiscovery(self, xml_host):
        xml_host_status_branch = xml_host.find('./status')
        status_state = xml_host_status_branch.attrib['state']
        status_reason = xml_host_status_branch.attrib['reason']


        # Mark host as up
        if status_state == 'up':
            if status_reason == 'user-set':  # user-set means scan was forced
                return

            logger.info('Host detected as online.  Reason: %s', status_reason)
            self.online = True
            self.save()

        logger.info('Host is not online')

    # host is not detected, but discovery from other sites might detect it



class NetworkDiscovery(models.Model):
    scanDate       = models.DateTimeField(default=django_timezone.now)
    site           = models.ForeignKey('Site', on_delete=models.PROTECT)
    sourceAddress  = models.CharField(max_length=40)
    scanHost       = models.CharField(max_length=100)
    nmap_version   = models.CharField(max_length=10)
    starttime      = models.IntegerField(null=True, blank=True)
    finishedtime   = models.IntegerField(null=True, blank=True)
    hostDiscoveries   = models.ManyToManyField('HostDiscovery', blank=True)
    hosts_up       = models.IntegerField()
    hosts_total    = models.IntegerField()
    complete       = models.BooleanField(default=False)
    xmlText        = models.TextField()

    class Meta:
        app_label = 'parasight'


    def __str__(self):
        return '{0:d}'.format(self.id)




class NetworkScan(models.Model):
    scanDate       = models.DateTimeField(default=django_timezone.now)
    site           = models.ForeignKey('Site', on_delete=models.PROTECT)
    sourceAddress  = models.CharField(max_length=40)
    scanHost       = models.CharField(max_length=100)
    hostScans      = models.ManyToManyField('HostScan', blank=True)
    numservices    = models.IntegerField()
    nmap_version   = models.CharField(max_length=10)
    starttime      = models.IntegerField(null=True, blank=True)
    finishedtime   = models.IntegerField(null=True, blank=True)
    scanType       = models.CharField(max_length=10)
    hosts_up       = models.IntegerField()
    hosts_total    = models.IntegerField()
    complete       = models.BooleanField(default=False)
    xmlText        = models.TextField()


    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:d} - {1:s}'.format(self.id, self.scanType)



class HostDiscovery(models.Model):
    scanDate       = models.DateTimeField(default=django_timezone.now)
    site           = models.ForeignKey('Site', on_delete=models.PROTECT)
    sourceAddress  = models.CharField(max_length=40)
    scanHost       = models.CharField(max_length=100, null=True, blank=True)
    nmap_version   = models.CharField(max_length=10)
    complete       = models.BooleanField(default=False)
    xmlText        = models.TextField(null=True, blank=True)

    class Meta:
        app_label = 'parasight'


    def __str__(self):
        return '{0:d}'.format(self.id)




def getHostScanReportPath(instance, filename):
    base_dir = Path('hostScanReport')

    now = datetime.now()
    new_filename = 'hostScanReport_{0:d}_{1:s}_{2:s}.xlsx'.format(instance.id, instance.hostname, now.strftime('%y%m%d_%H%M%S'))

    return base_dir.joinpath(str(instance.id), new_filename)


class HostScan(models.Model):
    scanDate       = models.DateTimeField(default=django_timezone.now)
    site           = models.ForeignKey('Site', on_delete=models.PROTECT)
    sourceAddress  = models.CharField(max_length=40)
    scanHost       = models.CharField(max_length=100, null=True, blank=True)
    numservices    = models.IntegerField()
    nmap_version   = models.CharField(max_length=10)
    hostname       = models.CharField(max_length=100, null=True, blank=True)
    scanPorts      = models.ManyToManyField('ScanPort', blank=True)
    refusedports   = models.IntegerField(null=True, blank=True)
    filteredports  = models.IntegerField(null=True, blank=True)
    starttime      = models.IntegerField(null=True, blank=True)
    endtime        = models.IntegerField(null=True, blank=True)
    scanType       = models.CharField(max_length=10)
    complete       = models.BooleanField(default=False)
    report         = models.FileField(upload_to=getHostScanReportPath, null=True, blank=True)
    xmlText        = models.TextField(null=True, blank=True)

    class Meta:
        app_label = 'parasight'


    def __str__(self):
        return '{0:d} - {1:s}'.format(self.id, self.scanType)



    def parseNmapScan(self, xml_host):
        starttime = int(xml_host.attrib['starttime'])
        endtime   = int(xml_host.attrib['endtime'])

        xml_host_extraports_branch = xml_host.find('./ports/extraports')

        extraports_state = xml_host_extraports_branch.attrib['state']
        if extraports_state == 'closed':
            refusedports_count = int(xml_host_extraports_branch.attrib['count'])
            filteredports_count = 0
        elif extraports_state == 'filtered':
            refusedports_count = 0
            filteredports_count = int(xml_host_extraports_branch.attrib['count'])
        else:
            filteredports_count = 0
            refusedports_count = 0
            logger.error('Unknown extraports state: %s', extraports_state)


        logger.info(' Refused ports found: %d', refusedports_count)
        logger.info(' Filtered ports found: %d', filteredports_count)


        xml_host_port_all = xml_host.findall('./ports/port')
        logger.info(' Reported ports: %d', len(xml_host_port_all))


        xml_host_hostname_branch = xml_host.findall('./hostnames/hostname')
        if xml_host_hostname_branch:
            hostname = xml_host_hostname_branch[0].attrib['name']
            logger.info(' Found hostname %s', hostname)
            self.hostname = hostname


        self.refusedports  = refusedports_count
        self.filteredports = filteredports_count
        self.starttime     = starttime
        self.endtime       = endtime
        self.save()



        # Create the open port objects for scan
        for xml_port in xml_host_port_all:
            xml_port_state_branch = xml_port.find('./state')

            portid_int = int(xml_port.attrib['portid'])
            port_state = xml_port_state_branch.attrib['state']

            if port_state != 'open':
                logger.info('  Port %d reported %s', portid_int, port_state)

            protocol = xml_port.attrib['protocol']


            logger.info('  Port %d/%s %s', portid_int, protocol, port_state)
            scan_port = ScanPort(
                port=portid_int,
                protocol=protocol,
                state=port_state,
            )
            scan_port.save()

            self.scanPorts.add(scan_port)



            xml_port_service_branch = xml_port.find('./service')

            if xml_port_service_branch:
                service_name = xml_port_service_branch.attrib.get('name', 'Unknown')
                logger.info('   Service: %s', service_name)

                # Create the service info objects for open port
                for service_key in xml_port_service_branch.attrib.keys():
                    if service_key in FILTER_SERVICE_KEYS:
                        continue

                    service_info = ScanPortServiceInfo(
                        key=service_key,
                        value=xml_port_service_branch.attrib[service_key],
                    )
                    service_info.save()

                    scan_port.serviceInfo.add(service_info)
            else:
                logger.info('   Service:  Not detected')


        self.complete = True
        self.save()


    def generateHostScanReport(self):

        # Excel
        wb = Workbook(write_only=True)
        wb.iso_dates = True

        ws = wb.create_sheet()
        ws.title = self.host_set.first().address
        ws.append(['Hostname', self.host_set.first().address])
        ws.append(['Scan Date', self.scanDate.replace(tzinfo=None)])
        ws.append(['Nmap', self.nmap_version])


        file_data = io.BytesIO()
        wb.save(file_data)

        self.report = ContentFile(file_data.read())
        self.save()


class ScanPort(models.Model):
    port           = models.IntegerField()
    protocol       = models.CharField(max_length=10)
    serviceInfo    = models.ManyToManyField('ScanPortServiceInfo', blank=True)
    state          = models.CharField(max_length=10)

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        if self.serviceInfo:
            try:
                name = self.serviceInfo.get(key='name').value
            except ScanPortServiceInfo.DoesNotExist:
                name = ''

            try:
                product = self.serviceInfo.get(key='product').value
            except ScanPortServiceInfo.DoesNotExist:
                product = ''

            try:
                version = self.serviceInfo.get(key='version').value
            except ScanPortServiceInfo.DoesNotExist:
                version = ''

            return '{0:d}/{1:s} - {2:s} ({3:s} - {4:s} - {5:s})'.format(self.port, self.protocol, self.state, name, product, version)

        return '{0:d}/{1:s} - {2:s}'.format(self.port, self.protocol, self.state)


    def getHostScan(self):
        return self.hostscan_set.first()


    def getHost(self):
        host_scan = self.getHostScan()

        if not host_scan:
            return None

        return host_scan.host_set.first()


    def getSite(self):
        host_scan = self.getHostScan()

        if not host_scan:
            return None

        return host_scan.site


    def getServiceInfo(self, key):
        serviceInfo = self.serviceInfo.filter(key=key)

        return serviceInfo.first()


class ScanPortServiceInfo(models.Model):
    key            = models.CharField(max_length=10)
    value          = models.TextField()

    class Meta:
        app_label = 'parasight'

    def __str__(self):
        return '{0:d} - {1:s}'.format(self.id, self.key)



