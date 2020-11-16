import dns.resolver
import sys
import argparse
import os
import re
import requests


def validate_path_in_command_line_option(input_path):
    """
    Validates a path provided in a command-line option 
    Inputs
    :param input_path: Input path provided in the command-line
    :return:
    """
    if not os.path.isfile(input_path):
        sys.stderr.write("File path {} doesn't exist. Please give a valid file path. \n".format(input_path))
        sys.exit()
    else:
        sys.stdout.write("File path {} is validated. \n".format(input_path))
        

def resolve_dns_name_to_ip_address(dns_name, dns_server):
    """
    Resolve a dns name specified in input parameter to return a list of IP addresses
    Inputs
    :param dns_name: DNS name
    :param dns_server: DNS server name
    :return: A list of IP addresses
    """
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    ip_addresses = []

    #dns name is resolved using user specified dns server name.
    try:
        dns.resolver.default_resolver.nameservers = [dns_server]
        result = dns.resolver.resolve(dns_name, 'A')
        for ipval in result:
            ip_addresses.append(ipval.to_text())
        sys.stdout.write("IP address for {}: {} \n".format(dns_name, ip_addresses))
        return ip_addresses
    
    except Exception as err:
        sys.stderr.write("Following exception occured - {}. \n".format(err))
        return None

def main()    
    parser = argparse.ArgumentParser(conflict_handler='resolve', description='Pass argument from command-line')
    parser.add_argument('--dns_server', type=str,  help='name or ip of the server to send DNS query to')
    parser.add_argument('--match', type=str, action='append', required=True, help='<path to file with value>=<glob pattern>') 
    parser.add_argument('--dns_name', type=str, required=True, help='dns name to inspect')
    parser.add_argument('--consul_key', type=str, required=True, help='consul key to modify')
    parser.add_argument('--consul_addr', type=str,  help='url of the consul api', \
                        default = os.getenv('CONSUL_ADDR', 'http://127.0.0.1:8500'))
    parser.add_argument('--consul_http_token', type=str, help='token to use for communication with consul', \
                        default = os.getenv('CONSUL_HTTP_TOKEN'))
    args = parser.parse_args()

    try:
        #Retrieve a list of IP addresses from DNS name
        IP_addresses = resolve_dns_name_to_ip_address(args.dns_name, args.dns_server)

        #File path validations 
        path_pattern = list(map(lambda t: tuple(t.split('=', 1)), args.match))
        for path in path_pattern:
            validate_path_in_command_line_option(path[0])
            
        #If any IP from the list matches a pattern, write the value previously read from a
        #corresponding file to consul KV store under specified path
        for ip in IP_addresses:
            for pair in path_pattern:

                #Check if IP matches with patterns
                compiled_pattern = re.compile(pair[1])
                if compiled_pattern.match(ip):
                    sys.stdout.write("IP {} matches with reg ex pattern {}\n".format(ip, pair[1]))     
                    with open(pair[0],'r') as f:
                        value = f.read()
                                            
                    #write to consul KV store    
                    sys.stdout.write("Adding Consul KV store entry \n")
                    url = '{}/v1/kv/{}'.format(args.consul_addr, args.consul_key)
                    headers = {"X-Consul-Token": args.consul_http_token}
                    result = requests.request('PUT', url, data = value, headers = headers)
                    sys.stdout.write("Output of PUT request: {} \n".format(result))
                    
                else:
                    sys.stderr.write("No IP matching with reg ex pattern {} \n".format(pair[1]))
                    
    except Exception as e:
        sys.stderr.write("Following exception occured - {}. \n".format(e))    
    
if __name__ == '__main__':
    main()
