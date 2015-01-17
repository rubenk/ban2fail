'''
ban2fail.py

This script reads the systemd journal looking for invalid
ssh login attempts and publishes these on a MQTT queue
'''

__author__  = 'Ruben Kerkhof <ruben@tilaa.com>'
__license__ = 'GPLv2'
__version__ = '0.0.1'

import json
import re
import select
import socket

import paho.mqtt.client as paho
from systemd import journal

INVALID = re.compile(r'^Invalid user (?P<user>\w+) from (?P<ip>[0-9a-fA-F.:]+)$')


def main():
    fqdn = socket.getfqdn()
    client=paho.Client()
    client.connect('localhost')

    j = journal.Reader()
    j.add_match(_SYSTEMD_UNIT='sshd.service')
    j.add_match(_COMM='sshd')
    j.this_boot()
    j.seek_tail()
    j.get_previous()

    p = select.poll()
    p.register(j, j.get_events())

    while p.poll():
        if j.process() != journal.APPEND:
            continue

        for entry in j:
            message = entry['MESSAGE']
            time = entry['__REALTIME_TIMESTAMP']

            r = INVALID.match(message)
            if r is None:
                continue
            groups = r.groupdict()
            print(str(entry['__REALTIME_TIMESTAMP'] )+ ' ' + message)

            payload = {
                'host': fqdn,
                'time': str(time),
                'user': groups['user'],
                'ip': groups['ip'],
            }

            client.publish(topic='blacklist', payload=json.dumps(payload))


if __name__ == '__main__':
    main()
