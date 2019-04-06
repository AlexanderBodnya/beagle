## Beagle
<p>Beagle is a Python3 tool to hunt SMB and RPC information. Beagle can use null sessions (or creds) to identify open rpc interactions and open smb shares.</p>

### Requirement
Install the requirements.txt and make sure rpcclient is installed on your machine.

### Usage

#### Discovery
##### Find alive hosts with icmp:
```python3 -t 192.168.0.0/24 -m icmp```
##### Find alive hosts with ports:
```python3 -t 192.168.0.0/24 -m ports```
##### Skip finding alive hosts:
```python3 -t 192.168.0.0/24 -m skip```

#### Quiet
```python3 beagle.py -t 192.168.0.0/24 -q```

#### Verbose
```python3 beagle.py -t 192.168.0.0/24 -v```


#### Specifying credentials
Finding shares:```python3 beagle.py -t 192.168.0.0/24 -c 'username:password'```

### Sample output to file
```
Host: 10.10.11.46 [DC-WIN12] -- Null sessions: True -- Shares: ADMIN$, C$, IPC$, NETLOGON, shared, SYSVOL -- 
```

### Help page
```
usage: smbeagle.py [-h] -t  [-m] [-e] [-p] [-c] [-d] [-o] [-q] [-v]

Release the bagels.

optional arguments:
  -h, --help           show this help message and exit
  -t , --target        Takes single IP, CIDR or file.
  -m , --mode          Host discovery options: ICMP, Port, Skip
  -e , --enumerate     Enumerate options: Null, Shares, MS17-010, All.
  -p , --ports         Ports to scan. Comma seperated and dash seperated both
                       work
  -c , --credentials   Colon seperated credentials
  -d , --domain        Domain name of the hosts
  -o , --output        Output to file
  -q, --quiet          Disable a bunch of output
  -v, --verbose        Increase the spam
  ```
