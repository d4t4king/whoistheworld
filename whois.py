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
from ipwhois.exceptions import HTTPLookupError
from datetime import datetime,timedelta

#######################################
###    THIS SCRIPT USES SPACES!!!   ###
#######################################

error_nets = []

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
    sql = "CREATE TABLE IF NOT EXISTS whois (id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT, \
        name TEXT, handle TEXT, range TEXT, description TEXT, country TEXT, state TEXT, \
        city TEXT, address TEXT, postal_code TEXT, abuse_emails TEXT, tech_emails TEXT, \
        misc_emails TEXT, created INTEGER, updated INTEGER)"
    sqldb.exec_non_query(sql)
    sql = "CREATE TABLE IF NOT EXISTS error_nets (id INTEGER PRIMARY KEY AUTOINCREMENT, net TEXT, \
        net_end TEXT)"
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

        print current_ip

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
            print type(error), error
            #print dir(error)

            if "error code 404" in error.message:
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

        #pp.pprint(whois_resp)
        #exit(1)
        if 'asn_cidr' in whois_resp and \
            whois_resp['asn_cidr'] is not None and \
            whois_resp['asn_cidr'].count('.') == 3:
            last_netrange_ip = get_netrange_end(whois_resp['asn_cidr'])
        else:
            try:
                last_netrange_ip = \
                    whois_resp['network']['end_address'].strip()
                    #netrange.split('-')[-1].strip()
                assert last_netrange_ip.count('.') == 3
            except:
                # no match found for n + 192.0.1.0.
                print("Missing ASN CIDR in whois response: {0}".format(whois_resp))
                current_ip = get_next_ip(current_ip)

                if current_ip is None:
                    return # no more undefined ip addresses

                gevent.sleep(randint(sleep_min, sleep_max))
                continue
        assert last_netrange_ip is not None and \
            last_netrange_ip.count('.') == 3, \
            "Unable to find last netrange ip for {0}: {1}".format(current_ip,
                                                                  whois_resp)

        # This is where we would store the data in the db.
        # For now, just print it out and move on.
        #print("Net: {0}, Whois Response: \n{1}".format(current_ip, whois_resp))
        sqlite = sqliteUtils.sqliteUtils(dbfile)
        sql = ''

        match = re.search(r'^[0-9.]+$', whois_resp['asn_cidr'])
        if match:
            sql = "SELECT id FROM whois WHERE cidr LIKE '{0}%'".format(
                whois_resp['asn_cidr'])
        elif 'nets' in whois_resp.keys() and \
            re.search(r'^[0-9.]+$', whois_resp['nets'][0]['cidr']) is not None:
            sql = "SELECT id FROM whois WHERE cidr LIKE '{0}'".format(
                whois_resp['nets'][0]['cidr'])
        else:
            sql = "SELECT id FROM whois WHERE cidr LIKE '{0}%'".format(
                whois_resp['network']['cidr'])
        record_id = sqlite.exec_atomic_int_query(sql)
        created = 0
        updated = 0
        #pp.pprint(whois_resp['network'])
        if whois_resp['network']['events']:
            for evt in whois_resp['network']['events']:
                if 'last changed' in evt['action'] and \
                    not 'None' in evt['timestamp']:
                    updated = date_to_integer(evt['timestamp'])
                if 'registration' in evt['action'] and \
                    not 'None' in evt['timestamp']:
                    created = date_to_integer(evt['timestamp'])
        elif whois_resp['nets'][0]['updated'] and \
            whois_resp['nets'][0]['created']:
            if whois_resp['nets'][0]['updated'] is not None:
                updated = date_to_integer(whois_resp['nets'][0]['updated'])
            else:
                updated = 'None'
            if whois_resp['nets'][0]['created'] is not None:
                created = date_to_integer(whois_resp['nets'][0]['created'])
            else:
                created = 'None'
        description = ''
        #pp.pprint(whois_resp['network'])
        if whois_resp['network']['remarks']:
            if whois_resp['network']['remarks'][0]['description'] and \
                not 'None' in whois_resp['network']['remarks'][0]['description']:
                description = whois_resp['network']['remarks'][0]['description'].replace('\n', ' ')
        elif 'nets' in whois_resp.keys():
            if whois_resp['nets'][0]['description'] and \
                not 'None' in whois_resp['nets'][0]['description']:
                description = whois_resp['nets'][0]['description'].replace('\n', ' ')
        description = description.replace("'", "''")
        address = ''
        if whois_resp['objects']:
            for key in whois_resp['objects'].keys():
                #print(str(type(whois_resp['objects'])))
                if not 'None' in whois_resp['objects'][key]['contact']['address'][0]['value']:
                    address = whois_resp['objects'][key]['contact']['address'][0]['value'].replace('\n', ' ')
                    # just get the infor for the first object
                    break
        elif 'nets' in whois_resp.keys():
            if whois_resp['nets'][0]['address'] and \
                not 'None' in whois_resp['nets'][0]['address']:
                address = whois_resp['nets'][0]['address'].replace('\n', ' ')
        address = address.replace("'", "''")
        netrange = ''
        if whois_resp['network']['start_address'] and \
            whois_resp['network']['start_address'].count(',') == 3 and \
            whois_resp['network']['end_address'] and \
            whois_resp['network']['end_address'].count('.') == 3:
            netrange = "{0} - {1}".format(
                whois_resp['network']['start_address'],
                whois_resp['network']['end_address'])
        elif 'nets' in whois_resp.keys() and \
            whois_resp['nets'][0]['range'] is not None:
            netrange = whois_resp['nets'][0]['range']

        if not record_id or 'None' in str(record_id):
            if whois_resp['network']:
                m = re.search(r'^[0-9.]+$', whois_resp['asn_cidr'])
                # If asn_cidr looks like an ip, use that.  Otherwise
                # use the net cidr.
                if m:
                    sql = "INSERT INTO whois (cidr, name, handle, range, description, \
                        country, address, created, updated) VALUES ('%s', \
                        '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                        (whois_resp['asn_cidr'], \
                        whois_resp['network']['name'], whois_resp['network']['handle'], \
                        netrange, description, \
                        whois_resp['network']['country'], \
                        address, created, updated)
                else:
                    sql = "INSERT INTO whois (cidr, name, handle, range, description, \
                        country, address, created, updated) VALUES ('%s', \
                        '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                        (whois_resp['network']['cidr'], \
                        whois_resp['network']['name'], whois_resp['network']['handle'], \
                        netrange, description, \
                        whois_resp['network']['country'], \
                        address, created, updated)
            elif whois_resp['nets']:
                m = re.search(r'^[0-9.]+$', whois_resp['asn_cidr'])
                # If asn_cidr looks like an ip, use that.  Otherwise
                # use the net cidr.
                if m:
                    sql = "INSERT INTO whois (cidr, name, handle, range, description, \
                        country, address, created, updated) VALUES ('%s', \
                        '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                        (whois_resp['asn_cidr'], \
                        whois_resp['nets'][0]['name'], whois_resp['nets'][0]['handle'], \
                        netrange, description, \
                        whois_resp['nets'][0]['country'], \
                        address, created, updated)
                else:
                    sql = "INSERT INTO whois (cidr, name, handle, range, description, \
                        country, address, created, updated) VALUES ('%s', \
                        '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                        (whois_resp['nets'][0]['cidr'], \
                        whois_resp['nets'][0]['name'], whois_resp['nets'][0]['handle'], \
                        netrange, description, \
                        whois_resp['nets'][0]['country'], \
                        address, created, updated)
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
        #get_netranges('1.0.0.0', '255.255.255.255',
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
