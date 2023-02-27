#!/usr/bin/env python3

import django
import os
import sys


sys.path.append(os.path.abspath(os.path.dirname(sys.argv[0]) + '/../'))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

django.setup()

#import parasight
from parasight import tasks


t = tasks.NormalScanAllNetworks()
t.delay()
