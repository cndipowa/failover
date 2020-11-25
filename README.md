##Failover

Purpose of `failover` script is to change how services in aws-prod resolve their dependencies in bethesda and sterling.

Services in aws-prod should invoke their dependencies from either bethesda or sterling (whatever is "active")
but currently they are connected to sterling and bethesda at the same time at all times.

`failover` script is a Python application for inspecting an arbitrary dns name provided by user to resolve IP address.
And if resolved IP address matches a regular expression pattern provided by user, then invoke consul API to 
write the value (failover domain) previously read from a corresponding dtab file to consul KV store under specified path.


##Installation

Use the package manager pip to install requirements.

pip install -r requirements.txt

##Usage

Always refer to help for details (this README may become outdated)

```
$ ./failover.py -h
usage: failover.py [-h] [--consul-addr CONSUL_ADDR] [--consul-dc CONSUL_DC] [--consul-key CONSUL_KEY]
                   [--consul-http-token CONSUL_HTTP_TOKEN] [--dns-server DNS_SERVER] --match FILE=REGEX
                   DNS_NAME

Automatic fail-over detection script for DevOps Platform 1.0

positional arguments:
  DNS_NAME              dns name to inspect

optional arguments:
  -h, --help            show this help message and exit
  --consul-addr CONSUL_ADDR
                        address of the consul API. Respects CONSUL_ADDR env var (default: http://localhost:8500)
  --consul-dc CONSUL_DC
                        consul datacenter. Local API DC if None (default: None)
  --consul-key CONSUL_KEY
                        consul key to modify (default: __namerd__/dtabs/internal-failover)
  --consul-http-token CONSUL_HTTP_TOKEN
                        consul authentication token. Respects CONSUL_HTTP_TOKEN env var (default: None)
  --dns-server DNS_SERVER
                        address of the DNS server to use (default: None)
  --match FILE=REGEX    expression to associate file with regex to match DNS resolution result. Can be specified
                        multiple times (default: None)

```

For example:
```
$ export CONSUL_HTTP_TOKEN=XXXXXX-XXXX-XXXX-XXXX-XXXXXX

$ export CONSUL_ADDR=http://consul-prod701.ac-va.ncbi.nlm.nih.gov

$ cat ./bethesda.dtab
/resolve=>/bethesda-prod

$ cat ./sterling.dtab
/resolve=>/sterling-prod

$ ./failover \
  --dns-server='ns.nih.gov'
  --consul-key='__namerd__/dtabs/internal-failover' \
  --match='./bethesda.dtab=130\..*' \
  --match='./sterling.dtab=165\..*' \
  www.wip.ncbi.nlm.nih.gov
```

If executed like this, the script will resolve `www.wip.ncbi.nlm.nih.gov` via `ns.nih.gov` and 

* if any of the resulting IPs starts with `130.`, will write `/resolve=>/bethesda-prod` (the content of the
 `bethesda.dtab` file) to consul KV under the key `__namerd__/dtabs/internal-failover`; or else
* if any of the resulting IPs starts with `165.`, will write `resolve=>/sterling-prod` to the consul KV; or else
* will fail
