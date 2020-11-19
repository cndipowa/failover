#!/usr/bin/env python

import argparse
import consul
import dns.resolver
import logging
import os
import re
from urllib.parse import urlparse


def parse_match(match):
    """
    Validate path & compile reg ex pattern in match arguments
    Inputs
    :param match: match argument provided by user
    :return: a tuple of valid paths and compiled regexes
    """
    try:
        path, regex = tuple(match.split('=', 1))
        if not os.path.isfile(path):
            raise Exception(f"--match '{match}': '{path}' is not a file")
        re.compile(regex)
    except ValueError as ve:
        raise Exception(f"--match '{match}': format must be FILE=REGEX") from ve
    except re.error as re_error:
        raise Exception(f"--match '{match}': regex '{regex}' is not valid") from re_error
    return path, regex


def resolve(dns_server, dns_name):
    """
    Resolve dns name to ip address
    Inputs
    :param dns_server: dns server
    :param dns_name: dns name
    :return: a list resolved ip address
    """
    try:
        if dns_server:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.nameservers = [dns_server]
            dns.resolver.override_system_resolver(resolver)
        resolution = dns.resolver.resolve(dns_name, 'A')
        ips = list(map(lambda ip: ip.to_text(), resolution))
        logging.info(f"Resolved '{dns_name}' via {dns_server if dns_server else 'default resolver'} to {ips}")
        return ips
    except Exception as resolve_err:
        raise Exception("DNS name resolution failed") from resolve_err
    finally:
        # reset dns resolver back to system default
        dns.resolver.override_system_resolver(None)


def match_ip_pattern(ips, match_patterns):
    """
    Check if IP address resolved from dns name matches reg ex pattern
    Inputs
    :param ips: a list of resolved ip addresses
    :param match_patterns: a list of reg ex patterns to be matched
    :return: a list resolved ip address
    """
    for path, compiled_pattern in match_patterns:
        if any(filter(lambda ip: re.match(compiled_pattern, ip), ips)):
            logging.info(f"{path}={compiled_pattern} matched one of IPs in {ips}")
            return path
        else:
            logging.info(f"{path}={compiled_pattern} didn't match any IP")
    raise Exception(f"No IP has matched any of the specified match expressions.\n{ips}\n{match_patterns}")


def read(path):
    """
    Read the file
    Inputs
    :param path: file path
    :return: file content
    """
    with open(path, 'r') as f:
        content = f.read()
    return content


def write_to_consul(consul_api, key, value):
    """
    Write key value to consul kv store.
    Inputs
    :param consul_api: consul instance
    :param key: consul key
    :param value: value
    """
    logging.info(f"Writing to consul KV {key}={value}")
    try:
        ok = consul_api.kv.put(key, value)
        if not ok:
            raise Exception("Failed to write to consul KV")
    except Exception as consul_err:
        raise Exception("Failed to write to consul KV") from consul_err


def main():
    parser = argparse.ArgumentParser(description='Automatic fail-over detection script for DevOps Platform 1.0',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--consul-addr', type=str, help='address of the consul API. Respects CONSUL_ADDR env var',
                        default=os.getenv('CONSUL_ADDR', "http://localhost:8500"))
    parser.add_argument('--consul-dc', type=str, help='consul datacenter. Local API DC if None')
    parser.add_argument('--consul-key', type=str, help='consul key to modify',
                        default="__namerd__/dtabs/internal-failover")
    parser.add_argument('--consul-http-token', type=str,
                        help='consul authentication token. Respects CONSUL_HTTP_TOKEN env var',
                        default=os.getenv('CONSUL_HTTP_TOKEN'))
    parser.add_argument('--dns-server', type=str, help='address of the DNS server to use')
    parser.add_argument('--match', metavar='FILE=REGEX', type=str, action='append', required=True,
                        help='expression to associate file with regex to match DNS resolution result. '
                             'Can be specified multiple times')
    parser.add_argument('dns_name', metavar='DNS_NAME', type=str, help='dns name to inspect')
    args = parser.parse_args()
    logging.getLogger().setLevel(logging.INFO)

    # validate path & compile reg ex pattern in match arguments
    path_patterns = list(map(parse_match, args.match))
    # parse consul connection parameters
    consul_url = urlparse(args.consul_addr)

    # Retrieve a list of IP addresses from DNS name
    ips = resolve(args.dns_server, args.dns_name)

    # If any IP from the list matches a reg ex pattern, write the value read from a
    # corresponding file to consul KV store under specified path
    file = match_ip_pattern(ips, path_patterns)
    kv_value = read(file)

    logging.info(
        f"Connecting to consul to {consul_url.scheme}://{consul_url.hostname}:{consul_url.port} @ DC={args.consul_dc} "
        f"with {'token=*****' if args.consul_http_token else 'no token'}")
    consul_api = consul.Consul(host=consul_url.hostname, port=consul_url.port, scheme=consul_url.scheme,
                               dc=args.consul_dc, token=args.consul_http_token)

    write_to_consul(consul_api, args.consul_key, kv_value)


if __name__ == '__main__':
    main()
