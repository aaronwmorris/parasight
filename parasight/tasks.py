
import sys
import logging

#from celery import group
#from celery import chain
from celery import Task
from mysite import celery_app
from .models import *

from django.db.models import Q

logger = logging.getLogger(__name__)



class TestTask(Task):
    name = 'parasight.tasks.TestTask'


celery_app.register_task(TestTask())



class DiscoverAllHosts(Task):
    name = 'parasight.tasks.DiscoverAllHosts'

    def run(self):
        for network in Network.objects\
                .filter(enabled=True):

            logger.info('Network: %s', network.network)

            network.populateHosts()

            for host in network.hosts\
                    .filter(enabled=True)\
                    .filter(online=False)\
                    .filter(forceOnline=False):

                logger.info('Host: %s', host.address)

                for site in network.zone.sites\
                        .filter(enabled=True):

                    logger.info(
                        'Create discover task for %s at site %s on queue %s',
                        host.address,
                        site.name,
                        site.queue.name
                    )
                    task = DiscoverHostAtSite().si(host.id, site.id)
                    task.apply_async(queue=site.queue.name)


celery_app.register_task(DiscoverAllHosts())



class DiscoverHostAtSite(Task):
    name = 'parasight.tasks.DiscoverHostAtSite'

    def run(self, host_id, site_id):
        host = Host.objects.get(id=host_id)

        host.runDiscoveryAtSite(site_id)


celery_app.register_task(DiscoverHostAtSite())



class DiscoverAllNetworks(Task):
    name = 'parasight.tasks.DiscoverAllNetworks'

    def run(self):
        for network in Network.objects\
                .filter(enabled=True):

            logger.info('Network: %s', network.network)

            network.populateHosts()

            for site in network.zone.sites\
                    .filter(enabled=True):

                logger.info(
                    'Create network discover task for %s at site %s on queue %s',
                    network.network,
                    site.name,
                    site.queue.name
                )
                task = DiscoverNetworkAtSite().si(network.id, site.id)
                task.apply_async(queue=site.queue.name)


celery_app.register_task(DiscoverAllNetworks())




class DiscoverNetworkAtSite(Task):
    name = 'parasight.tasks.DiscoverNetworkAtSite'

    def run(self, network_id, site_id):
        network = Network.objects.get(id=network_id)

        network.runDiscoveryAtSite(site_id)


celery_app.register_task(DiscoverNetworkAtSite())




### START HOST SCANS ###

class AbstractScanAllHosts(Task):
    name = 'parasight.tasks.AbstractScanAllHosts'
    abstract = True

    _scan_class_str = None

    def run(self):
        for network in Network.objects\
                .filter(enabled=True):

            logger.info('Network: %s', network.network)

            for host in network.hosts\
                    .filter(enabled=True)\
                    .filter(
                        Q(online=True)
                        | Q(forceOnline=True)  # noqa: W503
                    ):

                logger.info('Host: %s', host.address)

                for site in network.zone.sites\
                        .filter(enabled=True):

                    logger.info(
                        'Create scan task for %s at site %s on queue %s',
                        host.address,
                        site.name,
                        site.queue.name
                    )

                    local_module = sys.modules[__name__]
                    task_class = getattr(local_module, self._scan_class_str)

                    task = task_class().si(host.id, site.id)
                    task.apply_async(queue=site.queue.name)

#celery_app.register_task(AbstractScanAllHosts())


class FastScanAllHosts(AbstractScanAllHosts):
    name = 'parasight.tasks.FastScanAllHosts'

    _scan_class_str = 'FastScanHostAtSite'


celery_app.register_task(FastScanAllHosts())



class NormalScanAllHosts(AbstractScanAllHosts):
    name = 'parasight.tasks.NormalScanAllHosts'

    _scan_class_str = 'NormalScanHostAtSite'


celery_app.register_task(NormalScanAllHosts())


class FullScanAllHosts(AbstractScanAllHosts):
    name = 'parasight.tasks.FullScanAllHosts'

    _scan_class_str = 'FullScanHostAtSite'


celery_app.register_task(FullScanAllHosts())




class AbstractScanHostAtSite(Task):
    name = 'parasight.tasks.AbstractScanHostAtSite'
    abstract = True

    _scan_method_str = None

    def run(self, host_id, site_id):
        host = Host.objects.get(id=host_id)

        scan_method = getattr(host, self._scan_method_str)

        scan_method(site_id)

#celery_app.register_task(AbstractScanHostAtSite())



class FastScanHostAtSite(AbstractScanHostAtSite):
    name = 'parasight.tasks.FastScanHostAtSite'

    _scan_method_str = 'fastScan'


celery_app.register_task(FastScanHostAtSite())



class NormalScanHostAtSite(AbstractScanHostAtSite):
    name = 'parasight.tasks.NormalScanHostAtSite'

    _scan_method_str = 'normalScan'


celery_app.register_task(NormalScanHostAtSite())


class FullScanHostAtSite(AbstractScanHostAtSite):
    name = 'parasight.tasks.FullScanHostAtSite'

    _scan_method_str = 'fullScan'


celery_app.register_task(FullScanHostAtSite())

### END HOST SCANS ###




### START NETWORK SCANS ###
class AbstractScanAllNetworks(Task):
    name = 'parasight.tasks.AbstractScanAllNetworks'
    abstract = True

    _scan_class_str = None

    def run(self):
        for network in Network.objects\
                .filter(enabled=True):

            logger.info('Network: %s', network.network)

            network.populateHosts()

            for site in network.zone.sites\
                    .filter(enabled=True):

                logger.info(
                    'Create scan task for %s at site %s on queue %s',
                    network.network,
                    site.name,
                    site.queue.name
                )

                local_module = sys.modules[__name__]
                task_class = getattr(local_module, self._scan_class_str)

                task = task_class().si(network.id, site.id)
                task.apply_async(queue=site.queue.name)

#celery_app.register_task(AbstractScanAllNetworks())


class FastScanAllNetworks(AbstractScanAllNetworks):
    name = 'parasight.tasks.FastScanAllNetworks'

    _scan_class_str = 'FastScanNetworkAtSite'


celery_app.register_task(FastScanAllNetworks())



class NormalScanAllNetworks(AbstractScanAllNetworks):
    name = 'parasight.tasks.NormalScanAllNetworks'

    _scan_class_str = 'NormalScanNetworkAtSite'


celery_app.register_task(NormalScanAllNetworks())


class FullScanAllNetworks(AbstractScanAllNetworks):
    name = 'parasight.tasks.FullScanAllNetworks'

    _scan_class_str = 'FullScanNetworkAtSite'


celery_app.register_task(FullScanAllNetworks())



class AbstractScanNetworkAtSite(Task):
    name = 'parasight.tasks.AbstractScanNetworkAtSite'
    abstract = True

    _scan_method_str = None

    def run(self, network_id, site_id):
        network = Network.objects.get(id=network_id)

        scan_method = getattr(network, self._scan_method_str)

        scan_method(site_id)

#celery_app.register_task(AbstractScanNetworkAtSite())



class FastScanNetworkAtSite(AbstractScanNetworkAtSite):
    name = 'parasight.tasks.FastScanNetworkAtSite'

    _scan_method_str = 'fastScan'


celery_app.register_task(FastScanNetworkAtSite())



class NormalScanNetworkAtSite(AbstractScanNetworkAtSite):
    name = 'parasight.tasks.NormalScanNetworkAtSite'

    _scan_method_str = 'normalScan'


celery_app.register_task(NormalScanNetworkAtSite())


class FullScanNetworkAtSite(AbstractScanNetworkAtSite):
    name = 'parasight.tasks.FullScanNetworkAtSite'

    _scan_method_str = 'fullScan'


celery_app.register_task(FullScanNetworkAtSite())
