#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import time
import socket
import asyncio
import json
import ipaddress

try:
	with open(os.path.expanduser('~/.config/uptime_hosts.rc')) as f:
		host_types = json.load(f)
except FileNotFoundError:
	host_types = {}

def format_seconds(seconds):
	"""
	from seconds produce a human readable string
	"""

	def format_item(num,width, cap):
		"""
		format a number with a caption
		"""
		if int(num) > 1:
			cap = f'{cap}s'
		num = f'{int(num)}'
		return f'{num.rjust(width)} {cap}'

	parts = []
	days = seconds // (24 * 3600)

	if days:
		if days > 1:
			cap = 'days'
		else:
			cap = 'day'
		n = f'{int(days)}'.rjust(4)
		parts.append(f'{n} {cap}')

	seconds %= (24 * 3600)

	hours = seconds // 3600
	if int(hours):
		parts.append(format_item(hours,2,'hour'))

	seconds %= 3600
	minutes = seconds // 60
	
	if int(minutes):
		parts.append(format_item(minutes,2,'minute'))
	
	seconds %= 60

	if int(seconds):
		parts.append(format_item(seconds,2,'second'))

		return ', '.join(parts)


def hostname():
	"""
	return the hostname of the computer we're running on
	"""
	return os.uname()[1].split('.')[0]


class Host:
	"""
	Host class
		init(kwargs):
			kwargs[host]=hostname 

		Properties:
			local - boolean whether the host is the local machine
			machtype - Linux or Darwin

	The host class encapsulates the details needed to access the 
	number of seconds running on the host. 

	Because linux and macos use different methods of representing the running time 
	of a system. Linux stores, as number of seconds since boot, the data in /proc/uptime. 
	Macos uses an epoch timestamp which is retrieve with sysctl. 
	"""
	def __init__(self,**kwargs):
		global host_types
		self.local = False
		self.machtype = None
		self.host = kwargs.get('host',None)
		if self.host.split()[0] == hostname() or self.host == 'localhost':
			self.local = True
		if self.host in host_types:
			self.machtype = host_types[self.host]
		else:
			self.machtype = self._get_machtype().title()
			host_types[self.host] = self.machtype
			with open(os.path.expanduser('~/.config/uptime_hosts.rc'),'w') as f:
				json.dump(host_types,f)
		
		if not self.machtype:
			raise RuntimeError(f"Cannot get machine type for {self.host}")
		self.ip = socket.gethostbyname(self.host)
		self.ip = ipaddress.ip_address(socket.gethostbyaddr(self.ip)[2][-1])
		if(self.ip == ipaddress.ip_address('127.0.0.1')):
			self.local = True


	def execute_command(self,cmd):
		"""
		execute command with subprocess. If not local, prepend to the command list 'ssh' and host.
		return subproess.call result. 
		"""
		cmd = cmd.split()		
		if self.local:
			result = subprocess.run(cmd, capture_output=True, text=True, check=False)
		else:
			result = subprocess.run(['ssh',self.host]+cmd, capture_output=True, text=True, check=False)
		return result.stdout.strip()

	def _get_machtype(self):
		'''
		get the machine type (linx or darwin) and cache as a property 
		'''
		if self.local:
			m = sys.platform
		else:
			m = self.execute_command('uname -s')
		return m

	def get_uptime_seconds(self):
		"""
		get the number of seconds the host has been running since. 
		"""
		result = None
		cmd = None
		if self.machtype == 'Darwin':
			cmd = 'sysctl -n kern.boottime'
		elif self.machtype == 'Linux':
			cmd = 'cat /proc/uptime'
		else:
			raise RuntimeError(f'machinetype "{self.machtype}" has no match in Darwin|Linux')
		if not cmd:
			raise Exception(f"No cmd string, machtype = {self.machtype}")
		
		result = self.execute_command(cmd)
		if not result:
			raise RuntimeError(f'no result from command execution')
		
		if self.machtype == 'Darwin':
			"""
			darwin returns a string with runtime seconds and user seconds. We just want the 
			seconds in field 3 - this is the epoch value at boot, so we subtract that from
			the current time and return that as seconds since boot. 
			"""
			secs = result.split()[3].strip(',')
			secs = float(secs)
			result = time.time() - secs

		elif self.machtype == 'Linux':
			result = result.strip().split()[0]

		try:
			result = float(result)
		except Exception as e:
			print(f'{type(e)} result of {cmd} cannot be converted to float, result = {result}')
		return result

	def get_formated_uptime(self):
		"""
		format collected information in a readable format, store all parameters in a dict
		"""
		mtype = self.machtype
		if mtype == 'Darwin':
			mtype = 'macOS'
		seconds = self.get_uptime_seconds()
		ipstr = f'{self.ip}'.ljust(16)
		istr = f'{self.host.ljust(10)} {ipstr}'
		hstr = f"{istr} {mtype.ljust(10)}".ljust(35)
		tstr = format_seconds(seconds)
		return {
			'host': self.host,
			'ip': ipaddress.ip_address(self.ip),
			'machtype': mtype,
			'uptime': seconds,
			'formatted': f"{hstr} {tstr}."
		}

async def do_uptime(results, host):
	'''
	collect information and append to results
	'''
	try:
		host = Host(host=host)
	except RuntimeError:
		print(f'Cannot get host information for {host}')
		return
	results.append(host.get_formated_uptime())

async def get_uptimes(hosts,sortkey, reverse):
	"""
	get, sort, and print results
	"""
	results = []
	tasks = [do_uptime(results,h) for h in hosts]
	await asyncio.gather(*tasks)
	if len(results) > 1:
		results = sorted(results, key=lambda d: d[sortkey], reverse=reverse)

	lines = [r['formatted'] for r in results]
	lines = '\n'.join(lines)
	print(f"\r           \r{lines}")

# let me format my messages
class HelpFormat(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

if __name__ == "__main__":
	epi = """
  Retrieve uptime for the local and remote hosts and print in an easy to read format. 
  if a host has not been seen before, it is queried for it's platform type which is then
  cached. This speeds up future lookups.

  Hosts may be specified that are either in your ~/.ssh/config, /etc/hosts or are resolveable 
  via dns or zeroconf. If no host is specified the current host is queried.

  Remote hosts are queried using SSH and you must have credentials set up for each host.
  See ssh(1) for more information on ssh. If you can ssh to a host without a password, then 
  it can be queried with this tool.

  Sorting: Sorting is done based on column names. The columns names are, in order of output: 
        host, ip, machtype, uptime
  Sorting is controlled via the -r and -s flags (See above)
"""
	desc = """SSH based multi-host uptime query tool"""
	choices = ['host','ip','machtype','uptime']
	choice_text = ', '.join(choices[:-1]) + ', or ' + choices[-1]
	choicehelp = f'sory by column: {choice_text}'
	hosts = [hostname()]
	parser = argparse.ArgumentParser(description=desc, epilog=epi,formatter_class=HelpFormat)
	parser.add_argument('-r','--reverse',action='store_true',default=False, help='sort in reverse order')
	parser.add_argument('-s','--sort', choices=choices, metavar='column', default='host', help=choicehelp)
	parser.add_argument('hosts',nargs='*', default=hostname(), type=str, help="get uptime(s) for host(s)", metavar="host")
	args = parser.parse_args()
	print("Please wait...",end="")
	sys.stdout.flush()
	if type(args.hosts) is list:
		hosts = args.hosts
	asyncio.run(get_uptimes(hosts,args.sort,args.reverse))
 