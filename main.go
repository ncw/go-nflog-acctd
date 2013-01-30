package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"path"
	"runtime"
	"time"
)

// Globals
var (
	// Flags
	IPv4SourceGroup  = flag.Int("ip4-src-group", 0, "NFLog Group to read IPv4 packets and account the source address")
	IPv4DestGroup    = flag.Int("ip4-dst-group", 0, "NFLog Group to read IPv4 packets and account the destination address")
	IPv6SourceGroup  = flag.Int("ip6-src-group", 0, "NFLog Group to read IPv6 packets and account the source address")
	IPv6DestGroup    = flag.Int("ip6-dst-group", 0, "NFLog Group to read IPv6 packets and account the destination address")
	IPv6PrefixLength = flag.Int("ip6-prefix-length", 64, "Size of the IPv6 prefix to account to, default is /64")
	Cpus             = flag.Int("cpus", 0, "Number of CPUs to use - default 0 is all of them")
	ChannelSize      = flag.Int("channel-size", 32768, "Size of buffer for incoming accounting packets")
	UseSyslog        = flag.Bool("syslog", false, "Use Syslog for logging")
	Debug            = flag.Bool("debug", false, "Print every single packet that arrives")
	Interval         = flag.Duration("interval", time.Minute*5, "Interval to log stats")
	LogDirectory     = flag.String("log-directory", "/var/log/accounting", "Directory to write accounting files to.")

	// Globals
	BaseName       = path.Base(os.Args[0])
	Version        = "0.1"
	DefaultMapSize = 1024
)

// Information about one direction for a single IP or range
type HalfAccount struct {
	Bytes   int64
	Packets int64
}

// Collect info about a single IP (or range)
type Account struct {
	Source HalfAccount
	Dest   HalfAccount
}

// We store the Account directly in the map which makes for more
// copying but less garbage

// Accounting for IP addresses
//
// The key is the net.IP which is a []byte converted to a string so it
// can be used as a hash key
type IpMap map[string]Account

// Dump the IpMap to the output as a CSV
func (Ips IpMap) Dump(w io.Writer) error {
	wb := bufio.NewWriter(w)
	_, err := fmt.Fprintf(wb, "IP,SourceBytes,SourcePackets,DestBytes,DestPackets\n")
	if err != nil {
		return err
	}
	for key, ac := range Ips {
		ip := net.IP(key)
		_, err := fmt.Fprintf(wb, "%s,%d,%d,%d,%d\n", ip, ac.Source.Bytes, ac.Source.Packets, ac.Dest.Bytes, ac.Dest.Packets)
		if err != nil {
			return err
		}
	}
	return wb.Flush()
}

// Accounting
type Accounting struct {
	Output chan *Packet
	Ips    IpMap
}

func NewAccounting(Output chan *Packet) *Accounting {
	a := &Accounting{
		Output: Output,
	}
	a.newMaps()
	return a
}

// Make a new map returning the old one
func (a *Accounting) newMaps() IpMap {
	OldIps := a.Ips
	a.Ips = make(IpMap, DefaultMapSize)
	return OldIps
}

func (a *Accounting) Run() {
	ip6mask := net.CIDRMask(*IPv6PrefixLength, 128)

	// Print the stats every Interval
	go func() {
		ch := time.Tick(*Interval)
		for {
			<-ch
			a.Ips.Dump(os.Stdout)
		}
	}()

	for p := range a.Output {
		if p.IpVersion == 6 {
			p.Addr = p.Addr.Mask(ip6mask)
		}
		// Convert the net.IP which is a []byte into a string
		// This won't be a nice UTF-8 string but will preserve
		// the bytes and can be used as a hash key
		key := string(p.Addr)
		ac := a.Ips[key]
		if p.Direction == IpSource {
			ac.Source.Bytes += int64(p.Length)
			ac.Source.Packets += 1
		} else {
			ac.Dest.Bytes += int64(p.Length)
			ac.Dest.Packets += 1
		}
		a.Ips[key] = ac
		if *Debug {
			log.Printf("%s\n", p)
		}
	}
}

// usage prints the syntax
func usage() {
	fmt.Fprintf(os.Stderr,
		"%s ver %s\n\n"+
			"Usage: %s [flags]\n\n"+
			"flags:\n\n",
		BaseName, Version, BaseName)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
}

// main
func main() {
	flag.Usage = usage
	flag.Parse()

	if *Cpus <= 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		runtime.GOMAXPROCS(*Cpus)
	}

	if *UseSyslog {
		w, err := syslog.New(syslog.LOG_INFO, BaseName)
		if err != nil {
			log.Fatalf("Failed to start syslog: %s", err)
		}
		log.SetFlags(0)
		log.SetOutput(w)
	}

	Output := make(chan *Packet, *ChannelSize)
	var nflogs []*NfLog

	config := func(Group int, IpVersion byte, Direction IpDirection) {
		if Group > 0 {
			log.Printf("Monitoring NFLog multicast group %d for IPv%d %s", Group, IpVersion, Direction)
			nflog := NewNfLog(Group, IpVersion, Direction, Output)
			nflogs = append(nflogs, nflog)
			go nflog.Loop()
		}
	}

	config(*IPv4DestGroup, 4, IpDest)
	config(*IPv4SourceGroup, 4, IpSource)
	config(*IPv6DestGroup, 6, IpDest)
	config(*IPv6SourceGroup, 6, IpSource)

	if len(nflogs) == 0 {
		log.Fatal("Not monitoring any groups - exiting")
	}

	// Loop forever accounting stuff
	log.Printf("Starting accounting")
	a := NewAccounting(Output)
	a.Run()
}
