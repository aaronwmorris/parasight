#!/usr/bin/env python3

import django
import os
import sys
import argparse


sys.path.append(os.path.abspath(os.path.dirname(sys.argv[0]) + '/../'))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

django.setup()

from parasight import models
#from parasight import tasks


class ImportNetworksForZone(object):

    def __init__(self, zone_name):

        try:
            self.zone = models.Zone.objects.get(name=zone_name)
        except models.Zone.DoesNotExist:
            raise


    def main(self, csv_file_o):
        lines = csv_file_o.readlines()
        csv_file_o.close()


        for line in lines:
            line = line.strip()


            try:
                network, description, staticRouted = line.split(',')
            except ValueError:
                staticRouted = False

                try:
                    network, description = line.split(',')
                except ValueError:
                    network = line
                    description = network


            # convert to boolean
            if staticRouted:
                staticRouted = True


            new_network = models.Network(
                network=network,
                description=description,
                enabled=True,
                zone=self.zone,
                staticRouted=staticRouted,
            )

            new_network.save()



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--csv",
        "-c",
        help="csv file",
        required=True,
        type=argparse.FileType('r'),
    )
    parser.add_argument(
        "--zone",
        "-z",
        help="zone",
        required=True,
        type=str,
    )

    args = parser.parse_args()


    inz = ImportNetworksForZone(
        args.zone,
    )

    inz.main(args.csv)

