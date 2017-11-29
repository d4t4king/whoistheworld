#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import json
import gevent
import ipcalc
import pprint
import socket
import struct
import argparse
import requests
import sqliteUtils
from time import strftime,gmtime
from random import randint
from ipwhois import IPWhois
from netaddr import IPNetwork
from ipwhois.exceptions import HTTPLookupError
from datetime import datetime,timedelta

#######################################
###    THIS SCRIPT USES SPACES!!!   ###
#######################################

error_nets = []

class NormalizedWhois(object):
    """
    This class takes the input from the IPWhois query
    and normalizes it into a standard interface for the
    rest of the script.  This should remove some of the
    ugliness when handling lookup_rdap() responses and
    the older lookup_whois() responses.
    """

    @staticmethod
    def ascii_raw():
        strObj = """
 _______  _______  ___      _______        ______    _______  _     _
|       ||       ||   |    |       |      |    _ |  |   _   || | _ | |
|  _____||    ___||   |    |    ___|      |   | ||  |  |_|  || || || |
| |_____ |   |___ |   |    |   |___       |   |_||_ |       ||       |
|_____  ||    ___||   |___ |    ___| ___  |    __  ||       ||       |
 _____| ||   |___ |       ||   |    |   | |   |  | ||   _   ||   _   |
|_______||_______||_______||___|    |___| |___|  |_||__| |__||__| |__|
        """
        return strObj

    @staticmethod
    def ascii_dict():
        strObj = """
     _______. _______  __       _______               _______   __    ______ .___________.
    /       ||   ____||  |     |   ____|             |       \ |  |  /      ||           |
   |   (----`|  |__   |  |     |  |__                |  .--.  ||  | |  ,----'`---|  |----`
    \   \    |   __|  |  |     |   __|               |  |  |  ||  | |  |         |  |
.----)   |   |  |____ |  `----.|  |    __            |  '--'  ||  | |  `----.    |  |
|_______/    |_______||_______||__|   (__)_____ _____|_______/ |__|  \______|    |__|     ______ ______
                                        |______|______|                                  |______|______|
        """
        return strObj

    @staticmethod
    def _date_to_integer(datestr):
        dt = 0
        m = re.search(r'(\d{4})-(\d\d?)-(\d\d?)T(\d\d):(\d\d):(\d\d)(Z|(?:\+|\-)\d\d:\d\d)', datestr)
        if m:
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), \
                int(m.group(4)), int(m.group(5)), int(m.group(6)))
        else:
            try:
                assert len(datestr) <= 8 and len(datestr) >= 6, \
                    "Not the right number of numerals to be a compressed \
                    date string (ex. YYYYMMDD).  Got %s" % datestr

                m = re.search(r'(\d{4})(\d)(\d)(\d)(\d)', datestr)
                if m:
                    if m.group(2) == 0:
                        mon = int(m.group(3))
                    else:
                        mon = int("{0}{1}".format(m.group(2), m.group(3)))
                    if m.group(4) == 0:
                        day = int(m.group(5))
                    else:
                        day = int("{0}{1}".format(m.group(4), m.group(5)))
                    dt = datetime(int(m.group(1)), mon, day)
                else:
                    raise Exception("Didn't match timestamp string! ({0})".format(datestr))
            except TypeError as error:
                print "Not expected type: {0}".format(type(datestr))
                raise error
            except Exception as error:
                raise error
        return dt

    def __init__(self, response):
        # just for debugging
        pp = pprint.PrettyPrinter(indent=4)
        self.raw = response
        # initialize attributes to avoid scope issues
        self.asn = ''
        self.asn_registry = ''
        self.range = ''
        self.asn_cidr = ''
        self.cidr = ''
        self.name = ''
        self.handle = ''
        self.isrdapresponse = False
        self.iswhoisresponse = False
        self.start_address = ''
        self.end_address = ''
        self.description = ''
        self.country = ''
        self.state = ''
        self.city = ''
        self.address = ''
        self.postal_code = ''
        self.updated = -1
        self.created = -1
        # is rdap response
        if 'network' in response.keys():
            self.isrdapresponse = True
            self.iswhoisresponse = False
            self.asn = response['asn']
            if not 'asn_cidr' in response.keys():
                self.asn_cidr = response['network']['cidr']
            else:
                self.asn_cidr = response['asn_cidr']
            self.cidr = response['network']['cidr']
            try:
                if 'events' in response['network'].keys() and \
                    response['network']['events'] is not None:
                    for evt in response['network']['events']:
                        if 'last changed' in evt['action'] and \
                            not 'None' in evt['timestamp']:
                            #print "Updated: ",
                            #pp.pprint(evt)
                            self.updated = self._date_to_integer(evt['timestamp'])
                        else:
                            self.updated = 'None'
                        if 'registration' in evt['action'] and \
                            not 'None' in evt['timestamp']:
                            #print "Created: ",
                            #pp.pprint(evt)
                            self.created = self._date_to_integer(evt['timestamp'])
                        else:
                            self.created = 'None'
            except TypeError as error:
                pp.pprint(response['network'])
                raise error
            except Exception as error:
                raise error
            if response['network']['remarks'] is not None:
                if 'description' in response['network']['remarks'][0].keys() and \
                    not 'None' in response['network']['remarks'][0]['description']:
                    desc = response['network']['remarks'][0]['description']
                    desc = desc.replace('\n', ' ')
                    desc = desc.replace("'", "''")
                    self.description = desc
                else:
                    self.description = 'None'
            else:
                self.description = 'None'

            for key in response['objects'].keys():
                addr = ''
                try:
                    if response['objects'][key]['contact'] is not None:
                        if response['objects'][key]['contact']['address'] is None:
                            self.address = 'None'
                        elif response['objects'][key]['contact']['address'][0]['value'] is not None:
                            addr = response['objects'][key]['contact']['address'][0]['value'].replace('\n', ' ')
                            addr = addr.replace("'", "''")
                            self.address = addr
                        else:
                            self.address = 'None'
                        break
                except AttributeError as error:
                    pp.pprint(response['objects'][key])
                    raise error
                except TypeError as error:
                    pp.pprint(response['objects'][key])
                    raise error

            if response['network']['start_address'] is not None and \
                response['network']['start_address'].count('.') == 3 and \
                response['network']['end_address'] is not None and \
                response['network']['end_address'].count('.') == 3:
                self.range = "{0} - {1}".format(
                    response['network']['start_address'],
                    response['network']['end_address']
                )
            else:
                self.range = 'None'
            self.start_address = response['network']['start_address']
            self.end_address = response['network']['end_address']
            self.name = response['network']['name']
            self.handle = response['network']['handle']
            if response['network']['country'] is not None:
                self.country = response['network']['country'].upper()
            else:
                self.country = response['network']['country']
            self.city = 'None'
            self.state = 'None'
            self.postal_code = 'None'
        elif 'nets' in response.keys():
            self.iswhoisresponse = True
            self.isrdapresponse = False
            self.asn = response['asn']
            if not 'asn_cidr' in response.keys():
                self.asn_cidr = response['nets'][0]['cidr']
            else:
                self.asn_cidr = response['asn_cidr']
            self.cidr = response['asn_cidr']
            if 'list' in str(type(response['nets'])) and \
                len(response['nets']) == 0:
                    # no nets in response
                    return
            else:
                try:
                    if response['nets'][0]['created'] is not None:
                        #print "Created: ",
                        #pp.pprint(response['nets'][0])
                        self.created = self._date_to_integer(response['nets'][0]['created'])
                    else:
                        self.created = 'None'
                except TypeError as error:
                    pp.pprint(response['nets'])
            if response['nets'][0]['updated'] is not None:
                #print "Updated: ",
                #pp.pprint(response['nets'][0])
                self.updated = self._date_to_integer(response['nets'][0]['updated'])
            else:
                self.updated = 'None'
            if response['nets'][0]['description'] is not None:
                desc = response['nets'][0]['description'].replace('\n', ' ')
                desc = desc.replace("'", "''")
                self.description = desc
            else:
                self.description = 'None'
            if response['nets'][0]['address'] is not None:
                addr = response['nets'][0]['address'].replace('\n', ' ')
                addr = addr.replace("'", "''")
                self.address = addr
            else:
                self.address = 'None'
            if len(response['nets']) > 0:
                self.range = response['nets'][0]['range']
            else:
                self.range = 'None'
            self.start_address = \
                response['nets'][0]['range'].split('-')[0].strip()
            try:
                assert self.start_address is not None and \
                    self.start_address.count('.') == 3, \
                    "Unable to find start address for {0}: {1}".format(
                        response['nets'][0]['range'], response
                    )
            except AssertionError as error:
                if response['nets'][0]['range'] is not None and \
                    self.start_address.count('/') == 1:
                    (net,mask) = response['nets'][0]['range'].split('/')
                    if net.count('.') == 3:
                        self.start_address = net
                    elif net.count('.') == 2:
                        self.start_address = "{0}.0".format(net)
                    elif net.count('.') == 1:
                        self.start_address = "{0}.0.0".format(net)
                    else:
                        raise(error)
                else:
                    raise(error)
            self.end_address = \
                response['nets'][0]['range'].split('-')[-1].strip()
            try:
                assert self.end_address is not None and \
                    self.end_address.count('.') == 3, \
                    "Unable to find end address for {0}: {1}".format(
                        response['nets'][0]['range'], response
                    )
            except AssertionError as error:
                if response['nets'][0]['range'] is not None and \
                    self.end_address.count('/') == 1:
                    (net,mask) = response['nets'][0]['range'].split('/')
                    print("Net: {0}, Mask: {1}".format(net, mask))
                    if net.count('.') == 3 and \
                        int(mask) == 32:
                        self.end_address = net
                    elif net.count('.') == 2:
                        parts = net.split('.')
                        if int(mask) == 24:
                            self.end_address = "{0}.{1}.{2}.255".format(
                                parts[0], parts[1], parts[2]
                            )
                        elif  int(mask) == 22:
                            finip = "{0}.{1}.{2}.0".format(
                                parts[0], parts[1], parts[2]
                            )
                            ipnet = IPNetwork("{0}/{1}".format(finip, mask))
                            print "IP: {0}, CIDR: {1}, Bdcst: {2}".format(
                                ipnet.ip, ipnet.prefixlen, ipnet.broadcast
                            )
                            self.end_address = str(ipnet.broadcast)
                        else:
                            raise Exception("Unrecognized CIDR mask: {0}".format(mask))
                    elif net.count('.') == 1 and \
                        int(mask) == 16:
                        parts = net.split('.')
                        self.end_address = "{0}.{1}.255.255".format(
                            parts[0], parts[1]
                        )
                    else:
                        raise(error)
                else:
                    raise(error)
            self.name = response['nets'][0]['name']
            self.handle = response['nets'][0]['handle']
            if response['nets'][0]['country'] is not None:
                self.country = response['nets'][0]['country'].upper()
            else:
                self.country = response['nets'][0]['country']
            self.city = response['nets'][0]['city']
            self.state = response['nets'][0]['state']
            self.postal_code = response['nets'][0]['postal_code']

    def __repr__(self):
        #print self.ascii_raw()
        #print self.raw
        #print "=" * 72
        strObj = """
asn_cidr: %s, cidr: %s, range: %s, name: %s, handle: %s,
isrdapresponse: %s, iswhoisresponse: %s, start_address: %s,
end_address: %s, description: %s, country: %s, state: %s,
city: %s, address: %s, postal_code: %s, updated: %s,
created: %s
        """ % (self.asn_cidr, self.cidr, self.range, self.name,
                self.handle, self.isrdapresponse, self.iswhoisresponse,
                self.start_address, self.end_address, self.description,
                self.country, self.state, self.city, self.address,
                self.postal_code, self.updated, self.created)
        return strObj

def handle_http_error(error):
    """
    This method is intended to get the HTTP error code and
    respond appropriately:
    400: determine if multi country
    404: mark as error net and move on
    """
    raise NotImplemented("This method is not yet implemented")

def ip2long(ip):
    """
    Convert IPv4 address in string format into an integer

    :param str ip: ipv4 address

    :return ipv4 address
    :rtype integer
    """
    packed_ip = socket.inet_aton(ip)
    return struct.unpack("!L", packed_ip)[0]


def db_setup(dbfile='.whoisinfo.db'):
    print("Using dbfile {0}.".format(dbfile))
    sqldb = sqliteUtils.sqliteUtils(dbfile)
    sql = "CREATE TABLE IF NOT EXISTS whois (id INTEGER PRIMARY KEY AUTOINCREMENT, \
        asn INTEGER, asn_cidr TEXT, cidr TEXT, start_address TEXT, end_address TEXT, \
        name TEXT, handle TEXT, range TEXT, description TEXT, country TEXT, state TEXT, \
        city TEXT, address TEXT, postal_code TEXT, abuse_emails TEXT, tech_emails TEXT, \
        misc_emails TEXT, created INTEGER, updated INTEGER)"
    sqldb.exec_non_query(sql)
    sql = "CREATE TABLE IF NOT EXISTS error_nets (id INTEGER PRIMARY KEY AUTOINCREMENT, \
        net TEXT, net_end TEXT, http_error INTEGER, http_error_code INTEGER)"
    sqldb.exec_non_query(sql)


def date_to_integer(datestr):
    m = re.search(r'(\d{4})-(\d\d?)-(\d\d?)T(\d\d):(\d\d):(\d\d)(Z|(?:\+|\-)\d\d:\d\d)', datestr)
    if m:
        #if m.group(7) == 'Z':
        dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), \
            int(m.group(4)), int(m.group(5)), int(m.group(6)))
        #else:
        #    n = re.search(r'^(\+|\-)\d(\d):(\d\d)$', m.group(7))
        #    if n:
        #        # got a timezone offset
        #        #tz = int("".join([n.group(1), n.group(2), n.group(3)]))
        #        #print(str(tz))
        #        tdhours = int("".join([n.group(1), n.group(2)]))
        #        tdmins = int(n.group(3))
        #        print("===>>> H: {0} M: {1}".format(tdhours, tdmins))
        #        tz = timedelta(hours=tdhours, minutes=tdmins)
        #        print(str(int(tz.total_seconds())))
        #        dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), \
        #            int(m.group(4)), int(m.group(5)), int(m.group(6)), int(tz.total_seconds()))
        #    else:
        #        raise Exception("Didn't match timezone offset! ({0})".format(m.group(7)))
    else:
        raise Exception("Didn't match timestamp string! ({0})".format(datestr))
    return dt


def get_next_ip(ip_address):
    """
    :param str ip_address: ipv4 address
    :return: next ipv4 address
    :rtype: str
    >>> get_next_ip('0.0.0.0')
    '0.0.0.1'
    >>> get_next_ip('24.24.24.24')
    '24.24.24.25'
    >>> get_next_ip('24.24.255.255')
    '24.25.0.0'
    >>> get_next_ip('255.255.255.255') is None
    True
    """
    assert ip_address.count('.') == 3, \
        'Must be an IPv4 address in str representation'

    if ip_address == '255.255.255.255':
        return None

    try:
        return socket.inet_ntoa(struct.pack('!L', ip2long(ip_address) + 1))
    except Exception, error:
        print 'Unable to get next IP for %s' % ip_address
        raise error

def get_netrange_end(asn_cidr):
    """
    :param str asn_cidr: ASN CIDR
    :return: ipv4 address of last IP in netrange
    :rtype: str
    """
    try:
        last_in_netrange = \
            ip2long(str(ipcalc.Network(asn_cidr).host_first())) + \
            ipcalc.Network(asn_cidr).size() - 2
    except ValueError, error:
        print 'Issue calculating size of %s network' % asn_cidr
        raise error

    return socket.inet_ntoa(struct.pack('!L', last_in_netrange))

def get_next_undefined_address(ip):
    """
    Get the next non-private IPv4 address if the address sent is private
    :param str ip: IPv4 address
    :return: ipv4 address of net non-private address
    :rtype: str
    >>> get_next_undefined_address('0.0.0.0')
    '1.0.0.0'
    >>> get_next_undefined_address('24.24.24.24')
    '24.24.24.24'
    >>> get_next_undefined_address('127.0.0.1')
    '128.0.0.0'
    >>> get_next_undefined_address('255.255.255.256') is None
    True
    """
    try:
        # Should weed out many invalid IP addresses
        ipcalc.Network(ip)
    except ValueError, error:
        return None

    defined_networks = (
        '0.0.0.0/8',
        '10.0.0.0/8',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '255.255.255.255/32',
    )

    for network_cidr in defined_networks:
        if ip in ipcalc.Network(network_cidr):
            return get_next_ip(get_netrange_end(network_cidr))

    return ip

def break_up_ipv4_address_space(num_threads=8):
    """
    >>> break_up_ipv4_address_space() == \
     [('0.0.0.0', '31.255.255.255'), ('32.0.0.0', '63.255.255.255'),\
     ('64.0.0.0', '95.255.255.255'), ('96.0.0.0', '127.255.255.255'),\
     ('128.0.0.0', '159.255.255.255'), ('160.0.0.0', '191.255.255.255'),\
     ('192.0.0.0', '223.255.255.255'), ('224.0.0.0', '255.255.255.255')]
    True
    """
    ranges = []

    multiplier = 256 / num_threads

    for marker in range(0, num_threads):
        starting_class_a = (marker * multiplier)
        ending_class_a = ((marker + 1) * multiplier) - 1
        ranges.append(('%d.0.0.0' % starting_class_a,
                       '%d.255.255.255' % ending_class_a))

    return ranges

def get_netranges(starting_ip='1.0.0.0',
                    last_ip='2.0.0.0',
                    dbfile='.whoisinfo.db',
                    sleep_min=1, sleep_max=5):

    current_ip = starting_ip

    # pretty printer
    pp = pprint.PrettyPrinter(indent=4)

    while True:
        # see if we've finished the range of work
        if ip2long(current_ip) > ip2long(last_ip):
            return

        current_ip = get_next_undefined_address(current_ip)

        if current_ip == None:  # no more undefined addresses
            return

        #print current_ip

        whois_resp = ''
        try:
            #whois_resp = IPWhois(current_ip).lookup_rws()
            whois_resp = IPWhois(current_ip).lookup_rdap()
        except HTTPLookupError as error:
            """
            The advantage of catching specific errors, is that we
            can deal with specific problems specfically.

            In other words, if the RDAP look up fails because it
            can't find the requested IP address (HTTP/404), then
            try a "regular" whois lookup and see if that works.
            """
            #print type(error), error
            #print dir(error)

            if "error code 404" in error.message or \
                "error code 400" in error.message:
                try:
                    whois_resp = IPWhois(current_ip).lookup_whois()
                except Exception as error:
                    print type(error), error
                    #raise error

                    # The smallest IPv4 range that will be assigned by
                    # a RIR is /24.  So we should lookup the last IP
                    # for this range and get the next IP after that one.
                    if not current_ip in error_nets: error_nets.append(current_ip)
                    parts = current_ip.split('.')
                    net_end = ".".join([parts[0], parts[1], parts[2], '255'])
                    # database access object
                    sqlite = sqliteUtils.sqliteUtils(dbfile)
                    #print("Net end: {0}".format(net_end))
                    sql = "SELECT id FROM error_nets WHERE net='{0}' AND \
                            net_end='{1}'".format(current_ip, net_end)
                    #print(dir(sqlite))
                    record_id = sqlite.exec_atomic_int_query(sql)
                    if not record_id or 'None' in str(record_id):
                        sql = "INSERT INTO error_nets (net, net_end) VALUES \
                                ('{0}','{1}')".format(current_ip, net_end)
                        sqlite.exec_non_query(sql)

                    current_ip = get_next_ip(net_end)

                    if current_ip is None:
                        return # No more undefined ip addresses
                    # if we error'd out, don't sleep, just go right on to
                    # the next one
                    #gevent.sleep(randint(sleep_min, sleep_max))
                    continue
            else:
                pp.pprint(error)
                print("Error Message: {0}".format(error.message))
                raise error

        except Exception as error:
            """
            If a message like 'STDERR: getaddrinfo(whois.apnic.net): Name or
            service not known' then print it out and try the next
            IP address.
            """
            print type(error), error

            # The smallest IPv4 range that will be assigned by
            # a RIR is /24.  So we should lookup the last IP
            # for this range and get the next IP after that one.
            if not current_ip in error_nets: error_nets.append(current_ip)
            parts = current_ip.split('.')
            net_end = ".".join([parts[0], parts[1], parts[2], '255'])
            # database access object
            sqlite = sqliteUtils.sqliteUtils(dbfile)
            #print("Net end: {0}".format(net_end))
            sql = "SELECT id FROM error_nets WHERE net='{0}' AND \
                    net_end='{1}'".format(current_ip, net_end)
            #print(dir(sqlite))
            record_id = sqlite.exec_atomic_int_query(sql)
            if not record_id or 'None' in str(record_id):
                sql = "INSERT INTO error_nets (net, net_end) VALUES \
                        ('{0}','{1}')".format(current_ip, net_end)
                sqlite.exec_non_query(sql)

            current_ip = get_next_ip(net_end)

            if current_ip is None:
                return # No more undefined ip addresses
            # if we error'd out, don't sleep, just go right on to
            # the next one
            #gevent.sleep(randint(sleep_min, sleep_max))
            continue

        norm_resp = NormalizedWhois(whois_resp)
        #pp.pprint(norm_resp)
        #exit(1)
        if  norm_resp.asn_cidr is not None and \
            norm_resp.asn_cidr.count('.') == 3:
            last_netrange_ip = get_netrange_end(norm_resp.asn_cidr)
        else:
            try:
                last_netrange_ip = norm_resp.end_address
                assert last_netrange_ip.count('.') == 3
            except:
                # no match found for n + 192.0.1.0.
                print("Missing ASN CIDR in whois response: {0}".format(norm_resp.raw))
                #print(norm_resp.ascii_dict())
                #pp.pprint(norm_resp.__dict__)
                # The smallest IPv4 range that will be assigned by
                # a RIR is /24.  So we should lookup the last IP
                # for this range and get the next IP after that one.
                if not current_ip in error_nets:
                    error_nets.append(current_ip)
                parts = current_ip.split('.')
                net_end = ".".join([parts[0], parts[1], parts[2], '255'])
                # database access object
                sqlite = sqliteUtils.sqliteUtils(dbfile)
                #print("Net end: {0}".format(net_end))
                sql = "SELECT id FROM error_nets WHERE net='{0}' AND \
                        net_end='{1}'".format(current_ip, net_end)
                #print(dir(sqlite))
                record_id = sqlite.exec_atomic_int_query(sql)
                if not record_id or 'None' in str(record_id):
                    sql = "INSERT INTO error_nets (net, net_end) VALUES \
                            ('{0}','{1}')".format(current_ip, net_end)
                    sqlite.exec_non_query(sql)

                current_ip = get_next_ip(net_end)

                if current_ip is None:
                    return # No more undefined ip addresses
                # if we error'd out, don't sleep, just go right on to
                # the next one
                #gevent.sleep(randint(sleep_min, sleep_max))
                continue

        assert last_netrange_ip is not None and \
            last_netrange_ip.count('.') == 3, \
            "Unable to find last netrange ip for {0}: {1}".format(current_ip,
                                                                  norm_resp)

        # This is where we would store the data in the db.
        # For now, just print it out and move on.
        #print("Net: {0}, Whois Response: \n{1}".format(current_ip, whois_resp))
        sqlite = sqliteUtils.sqliteUtils(dbfile)
        sql = ''
        record_Id = 0

        if norm_resp.asn_cidr is not None:
            match = re.search(r'^[0-9.]+$', norm_resp.asn_cidr)
            if match:
                sql = "SELECT id FROM whois WHERE asn_cidr LIKE '{0}%'".format(
                    norm_resp.asn_cidr
                )
            else:
                sql = "SELECT id FROM whois WHERE cidr LIKE '{0}%'".format(
                    norm_resp.cidr)
        else:
            sql = "SELECT id FROM whois WHERE cidr LIKE '{0}%'".format(
                norm_resp.cidr)
        record_id = sqlite.exec_atomic_int_query(sql)

        if not record_id or 'None' in str(record_id):
            if norm_resp.isrdapresponse:
                sql = "INSERT INTO whois (asn, asn_cidr, cidr, name, \
                    handle, range, description, \
                    country, address, created, updated) VALUES ('%s', '%s', \
                    '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                    (norm_resp.asn, norm_resp.asn_cidr, norm_resp.cidr, \
                    norm_resp.name, norm_resp.handle, \
                    norm_resp.range, norm_resp.description, norm_resp.country, \
                    norm_resp.address, norm_resp.created, norm_resp.updated)
            else:
                sql = "INSERT INTO whois (asn, asn_cidr, cidr, name, \
                    handle, range, description, \
                    country, state, city, postal_code, address, created, \
                    updated) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', \
                    '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                    (norm_resp.asn, norm_resp.asn_cidr, norm_resp.cidr, \
                    norm_resp.name, norm_resp.handle, \
                    norm_resp.range, norm_resp.description, norm_resp.country, \
                    norm_resp.state, norm_resp.city, norm_resp.postal_code, \
                    norm_resp.address, norm_resp.created, norm_resp.updated)
            #print(sql)
            sqlite.exec_non_query(sql)

        current_ip = get_next_ip(last_netrange_ip)

        if current_ip is None:
            return # no more undefined ip addresses

        gevent.sleep(randint(sleep_min, sleep_max))


def main(argv):
    """
    :param dict argv: command line arguments
        (The original source did this, I don't know
        if it's really necessary since I'm handling
        arguments a different way, but we'll leave it
        for now.)
    """
    arg_parse = argparse.ArgumentParser(sys.argv[0])
    arg_parse.add_argument('action', type=str, nargs=1, metavar='action', \
        help="Action to take.  Valid options are 'collect' or 'stats'")
    arg_parse.add_argument('--sleep-min', type=int, dest='sleep_min', \
        default=1, help="Minimum thread sleep value in seconds.  \
        Default is 1.")
    arg_parse.add_argument('--sleep-max', type=int, dest='sleep_max', \
        default=5, help="Maximum thread sleep value in seconds.  \
        Default is 5.")
    arg_parse.add_argument('-t', '--threads', type=int, dest='num_threads', \
        default=8, help='Number of threads to use.  A good number seems \
        to be 4 threads per processor')
    arg_parse.add_argument('-d', '--dbfile', dest='dbfile', default='.whoisinfo.db', \
        type=str, help='The database file to use for sqlite.')
    args = arg_parse.parse_args()

    if 'collect' in args.action:
        db_setup(args.dbfile)

        threads = [gevent.spawn(get_netranges, starting_ip, ending_ip,
                    args.dbfile, args.sleep_min, args.sleep_max)
                    for starting_ip, ending_ip in
                        break_up_ipv4_address_space(args.num_threads)]

        gevent.joinall(threads)

        # single-thread mode for debugging
        # get_netranges('0.0.0.0', '255.255.255.255',
        #                args.dbfile, args.sleep_min,
        #                args.sleep_max)

    elif 'stats' in args.action:
        raise NotImplementedError("TODO!")
    else:
        raise Exception("Unrecognized action! ({0})".format(args.action))

if __name__ == '__main__':
    #try:
    main(sys.argv[1:])
    #except KeyboardInterrupt:
    #    pass
