## Beagle
<p>Beagle is a Python3 tool to hunt SMB and RPC information. Beagle can use null sessions (or creds) to identify open rpc interactions, open smb shares and the status of smb security.</p>

### Usage

#### Discovery
Find alive hosts with icmp:
```python3 -t 192.168.0.0/24 -m icmp```
Find alive hosts with ports:
```python3 -t 192.168.0.0/24 -m ports```
Skip finding alive hosts:
```python3 -t 192.168.0.0/24 -m skip```

#### Enumeration
##### Find null sessions:
```python3 beagle.py -t 192.168.0.0/24 -e null```
##### Find shares:
```python3 beagle.py -t 192.168.0.0/24 -e shares```
##### Find MS17-010:
```python3 beagle.py -t 192.168.0.0/24 -e ms17-010```
##### Find all:
```python3 beagle.py -t 192.168.0.0/24 -e all```

#### Specifying credentials
<p>If credentials are specified, Beagle will skip null sessions and enumerate shares and MS17-010 With those credentials.</p>
Finding shares:```python3 beagle.py -t 192.168.0.0/24 -e shares```
Finding MS17-010:```python3 beagle.py -t 192.168.0.0/24 -e ms17-010```
Find all:```python3 beagle.py -t 192.168.0.0/24 -e all```

### Help page
```
usage: beagle.py [-h] -t  [-m] [-e] [-p] [-U] [-P] [-q]

Release the bagels.

optional arguments:
  -h, --help         show this help message and exit
  -t , --target      Takes single IP, CIDR or file.
  -m , --mode        Host discovery options: ICMP, Port, Skip
  -e , --enumerate   Enumerate options: Null, Shares, MS17-010, All.
  -p , --ports       Ports to scan. Comma seperated and dash seperated both
                     work
  -U , --username    Username to authenticate with
  -P , --password    Password to authenticate with
  -q, --quiet        Disable a bunch of output
  ```