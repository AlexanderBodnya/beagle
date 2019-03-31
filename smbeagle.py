#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scapy.all import *
from netaddr import IPNetwork
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection
from lib import logger, banner
from subprocess import PIPE, run
import argparse

parser = argparse.ArgumentParser(description="Release the bagels.")
parser.add_argument("-t", "--target", required=True, metavar="", help="Takes single IP, CIDR or file.")
parser.add_argument("-m", "--mode", metavar="", help="Host discovery options: ICMP, Port, Skip")
parser.add_argument("-e", "--enumerate", metavar="", help="Enumerate options: Null, Shares, MS17-010, All.")
parser.add_argument("-p", "--ports", metavar="", help="Ports to scan. Comma seperated and dash seperated both work")
parser.add_argument("-c", "--credentials", metavar="", help="Colon seperated credentials")
parser.add_argument("-d", "--domain", metavar="", help="Domain name of the hosts")
parser.add_argument("-o", "--output", metavar="", help="Output to file")
parser.add_argument("-q", "--quiet",action="store_true", help="Disable a bunch of output")
parser.add_argument("-v", "--verbose",action="store_true", help="Increase the spam")
args = parser.parse_args()

class Host:
	def __init__(self, ip, name, shares, null_sessions):
		self.ip = ip #IP of the host
		self.name = name #NetBIOS name of the host
		self.shares = shares #list of shares
		self.null_sessions = null_sessions #null session boolean

def get_targets(targets):
#parses an input of targets to get a list of all possible ips
	target_list=[]

	if os.path.isfile(targets) == True:
		with open(targets,'r') as file:
			contents=file.readlines()
			for i in (contents):
				target=i.rstrip()
				target_list.append(target)
			logger.verbose('Amount of targets from input: {}'.format(len(target_list)))
			return target_list
	else:
		if "/" in targets:
			try:
				subnet=IPNetwork(targets)
			except:
				logger.red('failed to parse')
				quit()

			for i in subnet:
				tmp_str=str(i)
				last_octet=str(tmp_str.split('.')[3])
				if last_octet == '0' or last_octet == '255':
					pass
				else:
					target_list.append(str(i))
			logger.verbose('Amount of targets from input: {}'.format(len(target_list)))
			return target_list		

		else:
			target_list.append(targets)
			logger.verbose('Amount of targets from input: {}'.format(len(target_list)))
			return target_list


def error_handle(cmd_out):
	ERRORS=["NT_STATUS_CONNECTION_REFUSED","NT_STATUS_INVALID_NETWORK_RESPONSE","NT_STATUS_INVALID_PARAMETER","NT_STATUS_UNSUCCESSFUL","NT_STATUS_IO_TIMEOUT","NT_STATUS_ACCESS_DENIED","NT_STATUS_LOGON_FAILURE","NT_STATUS_REVISION_MISMATCH","COULD NOT CONNECT","NT_STATUS_HOST_UNREACHABLE","no servers could be reached"]
	val=False
	for error in ERRORS:
		if error in cmd_out:
			val=error #return the error if found
			logger.verbose('Found error from rpcclient: '.format(logger.YELLOW(val)))
			break
		else:
			val=False #otherwise, return False if no error is found
	if val == False:
		logger.verbose('Got no error from rpcclient')
	return val


def icmp_scan(targets):
	#takes in a list of targets and tries to identify a list of hosts responding to icmp and returns them in a list
	logger.verbose('Amount of targets for ICMP Scan: {}'.format(len(targets)))
	alive_hosts=[]
	timeout=2
	logger.verbose('ICMP Timeout set to: '+str(timeout))
	for target in targets:
		logger.blue('Pinging: {}'.format(logger.BLUE(target)))
		resp = sr1(IP(dst=str(target))/ICMP(),timeout=timeout,verbose=0)
		try:
			icmp_type=str(resp.getlayer(ICMP).code)
			resp_parse=icmp_response_parse(icmp_type)
			logger.verbose('Got ICMP Type: [{}] {}'.format(logger.YELLOW(icmp_type),logger.YELLOW(resp_parse)))
		except:
			logger.verbose('Could not get ICMP Type code for: '+logger.YELLOW(target))

		if resp is None:
			logger.verbose('Got no response from: '+logger.YELLOW(target))
			logger.red_indent('{}: Down'.format(logger.RED(target)))

		elif(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			logger.red_indent('{}: Down'.format(logger.RED(target)))

		else:
			logger.green_indent('{}: Up'.format(logger.GREEN(target)))
			if target not in alive_hosts:
				alive_hosts.append(target)
	return alive_hosts

def icmp_response_parse(resp):
	resp=int(resp)
	resp_codes= {
		0: 'Echo reply',
		3: 'Destination unreachable',
		4: 'Source quench',
		5: 'Redirect',
		8: 'Echo',
		9: 'Router advertisement',
		10: 'Router selection',
		11: 'Time exceeded',
		12: 'Parameter problem',
		13: 'Timestamp',
		14: 'Timestamp reply',
		15: 'Information request',
		16: 'Information reply',
		17: 'Address mask request',
		18: 'Address mask reply',
		30: 'Traceroute'
	}
	for code,msg in resp_codes.items():
		if resp == code:
			return msg

def get_name(target,timeout=5):
	logger.blue('Getting NetBIOS Name for {}'.format(logger.BLUE(target)))
	logger.verbose('Timeout for NetBIOS resolution: '+str(timeout))
	bios = NetBIOS()
	netbios_name = bios.queryIPForName(target, timeout=timeout)
	bios.close()
	if netbios_name == None:
		logger.red_indent('Failed to get NetBIOS Name')
		return None
	else:
		logger.green_indent('Got NetBIOS Name: {}'.format(logger.GREEN(*netbios_name)))
		return str(*netbios_name)

def get_shares(target,domain_name,remote_name,username,password):
	my_name='WIN-2003'
	logger.verbose('Client name configured to: '+logger.YELLOW(my_name))
	logger.blue('Looking up shares on {}'.format(logger.BLUE(target)))
	server_ip=target
	if remote_name != None:
		logger.verbose('Connection status: [{} | {} | {}]'.format(logger.YELLOW(server_ip),logger.YELLOW(remote_name),logger.YELLOW(domain_name)))
	else:
		logger.verbose('Connection status: [{} | {} | {}]'.format(logger.YELLOW(server_ip),logger.YELLOW('Could not resolve name'),logger.YELLOW(domain_name)))
	open_shares=[]
	if remote_name == None:
		logger.red_indent('Could not get remote hosts name, skipping...')
		return None
	else:
		conn = SMBConnection(username, password, my_name, remote_name, domain=domain_name, use_ntlm_v2=True,is_direct_tcp=True)
		logger.verbose('SMB configuration:')
		logger.verbose('\tConnecting with: {}'.format(logger.YELLOW(username)))
		for k,v in vars(conn).items():
			attribute=str(k)
			value=str(v)
			if '<class' not in value and 'bound method' not in value and 'object' not in value and "b''" not in value:
				logger.verbose('\t'+attribute+': '+value)
	try:
		conn.connect(server_ip,445)
		logger.green('Successfully connected to {} on {}'.format(logger.GREEN('smb'),logger.GREEN(server_ip)))

		try:
			shares=conn.listShares(timeout=15)
			for share in range(len(shares)):
				share_name=str(shares[share].name)
				logger.green_indent_list(logger.GREEN(share_name))
				open_shares.append(share_name)
		except Exception as e:
			logger.red_indent('Got error: {}'.format(logger.RED(e)))

	except:
		logger.red_indent('Failed to obtain shares from {}'.format(logger.RED(server_ip)))

	return open_shares

def get_nullsessions(target):
	logger.blue('Testing null sessions on {}'.format(logger.BLUE(target)))
	rpc_command_lsaquery='rpcclient -U "" -N {} -c "lsaquery"'.format(target)
	result=run(rpc_command_lsaquery,stdout=PIPE,stderr=PIPE,universal_newlines=False,shell=True)

	if len(result.stdout) > 0 and len(result.stderr) == 0:
		command_output=result.stdout
	elif len(result.stderr) > 0 and len(result.stdout) == 0:
		command_output=result.stderr

	decoded=command_output.decode('utf-8')
	has_error=error_handle(decoded)
	try:
		output=decoded.rstrip().replace('\n',' ')
		logger.verbose('Output from rpcclient: '+logger.YELLOW(str(output)))
	except:
		logger.verbose('Failed to get output from rpcclient')

	if has_error != False:
		logger.red_indent('Failed to authenticate with null sessions to {}'.format(logger.RED(target)))
		return False
	elif has_error == False:
		logger.green_indent('Successfully authenticated with null sessions to {}'.format(logger.GREEN(target)))
		return True

def output(outfile_name,ip,name,null_sessions,shares):
	with open (outfile_name,'a') as f:
		f.write('Host: {} [{}] -- '.format(ip,name))
		f.write('Null sessions: '+str(null_sessions)+' -- ')
		try:
			f.write('Shares: '+', '.join(str(x) for x in shares)+' -- ')
		except TypeError:
			f.write('Shares: None'+' -- ')
		f.write('\n')

def clean_output(filename):
	open(filename,'w').close()

def port_scan(targets,ports):
	src_port = RandShort()
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	SYNACK = 0x12
	RSTACK = 0x14
	URG = 0x20
	ECE = 0x40
	CWR = 0x80

	alive_hosts=[]

	for target in targets:
		logger.blue('Checking TCP ports: {}'.format(logger.BLUE(target)))
		for port in ports:
			send_syn = sr1(IP(dst=target)/TCP(sport=src_port,dport=port,flags=SYN),verbose=0,timeout=2)
			if send_syn == None:
				logger.verbose('Recieved no TCP response from: '+logger.YELLOW(target))
				logger.red_indent('{}:{} [{}]'.format(logger.RED(target),logger.RED(str(port)),logger.RED('CLOSED')))
			elif(send_syn.haslayer(TCP)):
				if(send_syn.getlayer(TCP).flags == SYNACK):
					send_ack = sr(IP(dst=target)/TCP(sport=src_port,dport=port,flags=RST),verbose=0,timeout=2)
					logger.verbose('Recieved SYNACK from {}, responding with RST'.format(logger.YELLOW(target)))
					logger.green_indent('{}:{} [{}]'.format(logger.GREEN(target),logger.GREEN(str(port)),logger.GREEN('OPEN')))
					if target not in alive_hosts:
						logger.verbose('Found alive host: '+logger.YELLOW(target))
						alive_hosts.append(target)
				elif (send_syn.getlayer(TCP).flags == RSTACK):
					logger.verbose('Recieved RSTACK from: '+logger.YELLOW(target))
					logger.red_indent('{}:{} [{}]'.format(logger.RED(target),logger.RED(str(port)),logger.RED('CLOSED')))
				elif (send_syn.getlayer(TCP).flags == RST):
					logger.verbose('Recieved RST from: '+logger.YELLOW(target))
					logger.red_indent('{}:{} [{}]'.format(logger.RED(target),logger.RED(str(port)),logger.RED('CLOSED')))
	logger.verbose('Total amount of alive hosts found: '+logger.YELLOW(str(len(alive_hosts))))
	return alive_hosts

def main():
	if args.quiet:
		logger.QUIET=True

	elif args.verbose:
		logger.VERBOSE=True

	if args.verbose == True and args.quiet == True:
		logger.red('Cannot run quietly and verbosely...')
		quit()

	if args.ports:
		p=[]
		ports=args.ports
		if "-" in ports:
			try:
				start=int(ports.split('-')[0])
				end=int(ports.split('-')[1])
				for port in range(start,end+1):
					p.append(port)
			except:
					print('failed to split on "-"')
					quit()
		elif "," in args.ports:
			ports=[int(n) for n in args.ports.split(",")]
			p=ports

		elif len(args.ports) > 0 and "-" not in args.ports and "," not in args.ports:
			try:
				p.append(int(args.ports))
			except ValueError:
				print('Please specify an port number')
				quit()
		else:
			p=[53,88,139,445,464]

	if args.ports: logger.verbose('Ports configuration: '+str(p))


	if args.credentials:
		try:
			username=args.credentials.split(':')[0]
			password=args.credentials.split(':')[1]
		except:
			logger.RED('failed to split credentials')
			quit()
	else:
		username=''
		password=''

	logger.verbose('Username: '+logger.YELLOW(username))

	if args.domain:
		domain=args.domain
	else:
		domain='WORKGROUP'

	logger.verbose('Domain: '+logger.YELLOW(domain))

	target=args.target #to be replaced with argparse
	hosts=get_targets(target) #all possible hosts

	if args.mode != None:
		if args.mode.upper() == 'ICMP':
			logger.verbose('Discovery mode set to ICMP')
			alive_hosts=icmp_scan(hosts) #all hosts that respond to icmp
		elif args.mode.upper() == 'PORTS':
			logger.verbose('Discovery mode set to ports')
			alive_hosts=port_scan(hosts,p)
		elif args.mode.upper() == 'SKIP':
			logger.verbose('Discovery mode set to skip, scanning all {} hosts'.format(logger.YELLOW(str(len(hosts)))))
			alive_hosts=hosts
	else:
		logger.verbose('No discovery mode set, defaulting to ICMP')
		alive_hosts=icmp_scan(hosts) #all hosts that respond to icmp

	#create an empty list that will store all the Host objects
	enumerated_hosts=[]

	#for every host, do some enum; this could probably be done with multiprocessing
	for i in alive_hosts:
		ip=i
		name=get_name(ip)
		shares=get_shares(ip,domain,name,username,password)
		null_sessions=get_nullsessions(ip)

		host=Host(ip,name,shares,null_sessions)
		enumerated_hosts.append(host)

	if args.output:
		outfile_name=args.output
		clean_output(outfile_name)
		for host in enumerated_hosts: #for every host object, pass the attributes to output()
			output(outfile_name,host.ip,host.name,host.null_sessions,host.shares)

if __name__ == '__main__':
	try:
		banner.banner()
		main()
	except KeyboardInterrupt:
		print('KeyboardInterrupt detected, exiting...')
		quit()

