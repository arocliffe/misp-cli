#! /usr/bin/env python
from pymisp import PyMISP
import yaml
import os
import sys
import re
import requests
import argparse
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
import jinja2
import logging

requests.packages.urllib3.disable_warnings(SubjectAltNameWarning) 

def jinja_template(result):
    ctx = {
        'event': {
          'id':          result['Event']['id'],
          'title':       result['Event']['info'],
#          'creator':     result['Event']['event_creator_email'], #not available with events created outside our own Org
          'published':   result['Event']['published'],
          'count':       result['Event']['attribute_count'],
          'org':         result['Event']['Org']['name'],
          'attributes':  []
          }
    }
    for attr in result['Event']['Attribute']:
        innerDict = {
          'value':    attr['value'],
          'type':     attr['type'],
          'to_ids':   attr['to_ids'],
          'category': attr['category'],
          'comments': attr['comment']
          }

        ctx['event']['attributes'].append(innerDict)
    sys.stdout.write(jinja2.Template(args.jinja_string).render(ctx) + "\n")

def validate_config(config):
    ret=True
    for alias in config.keys():
        try:
            for entry in ['api_key', 'url', 'ssl_certificate']:
                config[alias][entry]
        except:
            sys.stderr.write('Missing a configuration entry for %s: %s' % (alias, entry))
            ret = False
    return ret

try:
    config = yaml.load(open(os.path.join(os.environ['HOME'], '.misp-cli.yaml')))
except Exception as err:
    sys.stderr.write('Unable to open/parse config file: %s\n' % err)
    sys.exit(1)

if not validate_config(config):
    sys.exit(1)

emlist = []
eventcount = []
matchescount = []

parser = argparse.ArgumentParser()
parser.add_argument("-e", dest="exact", help="Show exact matches only i.e. searching for 'r.exe' will not return 'rar.exe', 'spoolsvr.exe' etc. For use with SINGLE IOC search only.", action="store_true")
parser.add_argument("-a", dest="all", help="Show the status of all queried IOC's. For use with FILE IOC search only.", action="store_true")
parser.add_argument("-v", dest="verbose", help="Verbose Mode", action="store_true")
parser.add_argument("-f", dest="file", help="Specify a list of IOCs to check")
parser.add_argument("-s", dest="single", help="Specify a single IOC to check")
parser.add_argument("-m", dest="misp",
                    help="Select MISP instance to search: misppriv (default), barncat",
                    type=str, default="misppriv")
parser.add_argument("-event", dest="event", help="Select an event to query")
parser.add_argument("-o", dest="jinja_string", help='jinja2 template string - use as following: "{{ event.attributes|selectattr("type", "equalto", "md5")|join(", ", attribute="value")}}". Changing the attribute selector where appropriate (type/to_ids/category and associated flag). Only available with single event search at this time') 

args = parser.parse_args()

if not args.misp in config:
    sys.stderr.write('The MISP alias %s does not exist in config. Choices are: %s\n' \
                     % (args.misp, ','.join(config.keys())))
    sys.exit(1)

misp_url = config[args.misp]['url']
misp_key = config[args.misp]['api_key']
misp_crt = config[args.misp]['ssl_certificate']
misp = PyMISP(misp_url, misp_key, ssl=misp_crt)

loglvl = logging.DEBUG if args.verbose else logging.WARNING
logging.basicConfig(level=loglvl, format="%(asctime)s %(name)8s %(levelname)5s: %(message)s")


if args.file:
    sys.stdout.write("\nThe following attributes were found in MISP:\n\n")
elif args.single:
    sys.stdout.write('\nChecking MISP for attribute "{0}"\n\n'.format(args.single))


def main():
    if args.file:
        checkFile(args.file)
    elif args.event:
        checkEvent(args.event)
    else:
        checkSingle(args.single)
    if not args.exact and not args.event:
        sys.stdout.write("\nWARNING: Short/Generic search terms will return all events containing that value i.e. search for 'r.exe' will return 'rar.exe', 'spoolsvr.exe' etc. Use -e for EXACT matches only.\n")
    return

def checkFile(file):
    with open(file, 'r') as IOC_file:
        lines = IOC_file.read().splitlines()

#    for ioc in open(file):
        for ioc in lines:
            if '\\' in ioc:
                ioc_alt = re.sub('\\\\', '\\\\\\\\', ioc)
                result =  misp.search_all(ioc_alt)
            else:
                result =  misp.search_all(ioc)
            if 'response' not in result:
                emlist.append(ioc)
                continue
            for instance in result['response']:
                info = instance['Event']['info'].encode('utf-8')
                evt = str(instance['Event']['id'])
                for value in instance ['Event']['Attribute']:
                    if ioc == value['value']:
                        sys.stdout.write("{:<6} - {:<30} {:80s}\n".format(evt, ioc, info))
    if len(emlist) != 0:
        sys.stdout.write("\nThe following were NOT found in MISP:\n\n")
        for i in emlist:
            sys.stdout.write(i + "\n")

def checkSingle(ioc):
    if '\\' in ioc:
        ioc = re.sub('\\\\', '\\\\\\\\', ioc)
    result =  misp.search_all(ioc)
    if 'response' not in result:
        sys.stdout.write("Attribute not found in MISP\n")
        return
    for instance in result['response']:
        eventcount.append(instance['Event']['id'])
        if args.exact:
            for value in instance['Event']['Attribute']:
                if value['value'] == ioc:
                    matchescount.append(ioc)
                    if args.jinja_string:
                        jinja_template(instance)
                    else:
                        sys.stdout.write("    {:5s}  -   {:10s}\n".format(instance['Event']['id'], instance['Event']['info'].encode('utf-8')))
        elif args.jinja_string:
            jinja_template(instance)
        else:
            sys.stdout.write("    {:5s}  -   {:10s}\n".format(instance['Event']['id'], instance['Event']['info'].encode('utf-8')))
    if args.exact:
        sys.stdout.write("\nIn total - {0} match(es) found but is seen in wider context in {1} events. Try without -e to show these events\n\n".format(len(matchescount), len(eventcount)))


def checkEvent(events):
    result =  misp.get(events)
    try:
        if args.jinja_string:
            jinja_template(result)
        else:
            for attribute in result['Event']['Attribute']:
                sys.stdout.write(attribute['value'] + "\n")
    except KeyError:
        sys.stdout.write("No Event with ID {0}\n".format(events))

main()
