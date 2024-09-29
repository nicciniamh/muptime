# Multiple Uptime Client
SSH based multi-host uptime query tool

## Usage
`muptime [-h] [-r] [-s column] [host ...]`

### Flags
| Flag                | Meaning                                                             |
|---------------------|---------------------------------------------------------------------|
| -s, --sort <column> | Sort based on column. Valid columns are  host, ip, machtype, uptime |
| -r, --reverse       | Reverse sort                                                        |
| -h, --help          | Show usage help                                                     |
| host ...            | Show usage for host <host> <host>                                   |

*defaults are sort ascending by hostname, if no host is specified, use the host returned by uname.*

## Descritption
This program retrieves uptime for the local and remote hosts and print in an easy to read format.
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

## Example output

```duckie     192.168.1.155    macOS         5 days, 14 hours, 11 minutes, 46 seconds.
media      192.168.1.141    Linux       150 days, 12 hours, 24 minutes, 29 seconds.
pi3        192.168.1.130    Linux        56 days, 15 hours, 24 minutes, 44 seconds.
pi4        192.168.1.119    Linux        13 days, 14 hours, 44 minutes, 28 seconds.
pi5        192.168.1.79     Linux        10 days, 22 hours,  8 seconds.
piz        192.168.1.104    Linux       153 days,  6 hours, 48 minutes,  4 seconds.
```

## Supported Systems
Currently muptime understands macOS® and Linux® systems.

## Requirements
This program (script) requires no external python 
modules but must use Python 3.5 or higher. 

## License
Freeware

## Trademarks
macOS is ® Apple Computer Corporation

Linux is ® Linux Foundation 
