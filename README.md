% go-nflog-acctd(1) User Manual
% Nick Craig-Wood
% May 17, 2013

Go NFLOG accounting
===================

This is a program to do IP accounting using NFLOG under Linux iptables.

To use it you'll need to add some NFLOG rules into your iptables (and
ip6tables) and configure go-nflog-acctd to read them.  It will
periodically dump .csv files for you to analyse.

To monitor IPv4 to and from this host you might use

    iptables -A OUTPUT -j NFLOG --nflog-group 4 --nflog-range 20 --nflog-threshold 50 --nflog-prefix "IPv4out"
    iptables -A INPUT -j NFLOG --nflog-group 5 --nflog-range 20 --nflog-threshold 50 --nflog-prefix "IPv4in"

And to monitor IPv6 to and from this host you might use

    ip6tables -A OUTPUT -j NFLOG --nflog-group 6 --nflog-range 40 --nflog-threshold 50 --nflog-prefix "IPv6out"
    ip6tables -A INPUT -j NFLOG --nflog-group 7 --nflog-range 40 --nflog-threshold 50 --nflog-prefix "IPv6in"

You then configure go-nflog-acctd using the nflog groups you used in the iptables commands, eg

    sudo ./go-nflog-acctd  -interval 1h -ip4-dst-group=4 -ip4-src-group=5 -ip6-dst-group=6 -ip6-src-group=7

Note that go-nflog-acctd needs to run as root.

go-nflog-acct doesn't daemonize itself - you'll need to run it under supervisord or similar.

Usage
=====

    go-nflog-acctd [flags]

Important flags

The NFlog IDs to monitor.  These must match the ones in your iptables rules

    -ip4-dst-group=0: NFLog Group to read IPv4 packets and account the destination address
    -ip4-src-group=0: NFLog Group to read IPv4 packets and account the source address
    -ip6-dst-group=0: NFLog Group to read IPv6 packets and account the destination address
    -ip6-src-group=0: NFLog Group to read IPv6 packets and account the source address

By default IPv4 addresses are not aggregated and IPv6 addresses are
aggregated to /64.  Use -ip4-prefix-length and -ip6-prefix-length to
control this.

    -ip4-prefix-length=32: Size of the IPv4 prefix to account to, default is /32
    -ip6-prefix-length=64: Size of the IPv6 prefix to account to, default is /64

Control where and how often the stats are written

    -log-directory="/var/log/accounting": Directory to write accounting files to.
    -interval=5m0s: Interval to log stats

Misc settings

    -cpus=0: Number of CPUs to use - default 0 is all of them
    -syslog=false: Use Syslog for logging
    -cpuprofile="": Write cpu profile to file
    -debug=false: Print every single packet that arrives

Output format
-------------

The bandwidth logs are written in CSV format to /var/log/accounting by default

They are named by "start of period-end-of-period.csv" eg
"2013-02-11-150000_2013-02-11-160000.csv"

The logs always start with a header row then data.  IP addresses can
be IPv4 or IPv6 addresses, either of which can have been masked.

    Time,IP,SourceBytes,SourcePackets,DestBytes,DestPackets
    2013-02-11 15:00:00,2001:aaa:bbbb:ccc:dddd:eeee:f52:b974,53756,281,66277,245
    2013-02-11 15:00:00,2001:aaa:bbbb:ccc:dddd:eeee:2af7:aa9e,532072,3078,1342504,3279
    2013-02-11 15:00:00,192.168.0.22,76,1,76,1
    2013-02-11 15:00:00,192.168.0.42,100372,762,10888,105
    2013-02-11 15:00:00,192.168.0.26,76,1,76,1
    2013-02-11 15:00:00,192.168.0.22,10396412,159611,260251871,257171
    2013-02-11 15:00:00,2001:aaa:bbbb:ccc:dddd:eeee:1835:8103,7758,48,35987,47
    2013-02-11 15:00:00,192.168.0.19,1168,13,1414,9
    2013-02-11 15:00:00,2001:aaa:bbbb:ccc:dddd:eeee:7818:86a,1127817,9522,14265686,14061
    2013-02-11 15:00:00,2001:aaa:bbbb:ccc:dddd:eeee:5eb7:5f2f,125213,989,1214213,1237

Build
=====

Make sure you have [libnetfilter_log](http://www.netfilter.org/projects/libnetfilter_log/) installed.

On Debian/Ubuntu install like this

    sudo apt-get install libnetfilter-log-dev

Then this to create the go-nflog-acctd binary.

    go build

Live Testing
------------

In one window

    sudo  ./go-nflog-acctd  -interval 10s -ip4-dst-group=4 -ip4-src-group=5 -ip6-dst-group=6 -ip6-src-group=7 -cpuprofile z.prof

In another window

    sudo hping3 127.0.0.2 --syn -p 80 -s 53 --flood

And a third use top to monitor the CPU usage

Check correctness
-----------------

In one window

    sudo  ./go-nflog-acctd  -interval 1h -ip4-dst-group=4 -ip4-src-group=5 -ip6-dst-group=6 -ip6-src-group=7

In another

    sudo hping3 127.0.0.2 --syn -p 80 -s 53 --flood

Run for a while

Stop the hping3

Stop the go-nflog-acctd

Check to see that the number of packets in the .csv is the same (give
or take 1 or 2) as hping3 printed when it was quitted

Benchmark
---------

Use this to do micro-optimisations on the packet handling code

    go test -v -bench .

License
=======

This is free software under the terms of the MIT license (check the
COPYING file included in this package).

Contact and support
===================

The project website is at:

- https://github.com/ncw/go-nflog-acctd

There you can file bug reports, ask for help or contribute patches.

Authors
=======

- Nick Craig-Wood <nick@craig-wood.com>

Contributors
------------

- Your name goes here!
