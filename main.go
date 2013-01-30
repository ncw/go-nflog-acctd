package main

// FIXME write some stats every now and again - packets per second etc

// FIXME detect overflows?

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"
)

const (
	// Time format to output in CSV files
	// http://stackoverflow.com/questions/804118/best-timestamp-format-for-csv-excel
	CsvTimeFormat = "2006-01-02 15:04:05"
	// Format to use when making filenames
	FileTimeFormat = "2006-01-02-15-04-05"
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
	UseSyslog        = flag.Bool("syslog", false, "Use Syslog for logging")
	Debug            = flag.Bool("debug", false, "Print every single packet that arrives")
	Interval         = flag.Duration("interval", time.Minute*5, "Interval to log stats")
	LogDirectory     = flag.String("log-directory", "/var/log/accounting", "Directory to write accounting files to.")
	CpuProfile       = flag.String("cpuprofile", "", "Write cpu profile to file")

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
type IpMap map[string]*Account

// Dump the IpMap to the output as a CSV
func (Ips IpMap) Dump(w io.Writer, when time.Time) error {
	wb := bufio.NewWriter(w)
	whenString := when.Format(CsvTimeFormat)
	_, err := fmt.Fprintf(wb, "Time,IP,SourceBytes,SourcePackets,DestBytes,DestPackets\n")
	if err != nil {
		return err
	}
	for key, ac := range Ips {
		ip := net.IP(key)
		_, err := fmt.Fprintf(wb, "%s,%s,%d,%d,%d,%d\n", whenString, ip, ac.Source.Bytes, ac.Source.Packets, ac.Dest.Bytes, ac.Dest.Packets)
		if err != nil {
			return err
		}
	}
	return wb.Flush()
}

// Returns the time rounded down to *Interval
func FlooredTime(t time.Time) time.Time {
	ns := t.UnixNano()
	ns /= int64(*Interval)
	ns *= int64(*Interval)
	return time.Unix(0, ns)
}

// Accounting
type Accounting struct {
	sync.Mutex
	StartPeriod time.Time
	EndPeriod   time.Time
	Ips         IpMap
}

func NewAccounting() *Accounting {
	a := &Accounting{}
	a.newMaps()
	return a
}

// Make a new map returning the old one while holding the lock
func (a *Accounting) newMaps() IpMap {
	a.Lock()
	defer a.Unlock()
	OldIps := a.Ips
	a.Ips = make(IpMap, DefaultMapSize)
	return OldIps
}

var ip6mask = net.CIDRMask(*IPv6PrefixLength, 128)

// Account a single packet in a thread safe way
func (a *Accounting) Packet(Direction IpDirection, Addr net.IP, Length int, IpVersion byte) {
	if IpVersion == 6 {
		Addr = Addr.Mask(ip6mask)
	}
	// Convert the net.IP which is a []byte into a string
	// This won't be a nice UTF-8 string but will preserve
	// the bytes and can be used as a hash key
	key := string(Addr)
	a.Lock()
	ac := a.Ips[key]
	if ac == nil {
		ac = &Account{}
		a.Ips[key] = ac
	}
	if Direction == IpSource {
		ac.Source.Bytes += int64(Length)
		ac.Source.Packets += 1
	} else {
		ac.Dest.Bytes += int64(Length)
		ac.Dest.Packets += 1
	}
	a.Unlock()
	if *Debug {
		log.Printf("IPv%d message %s Addr %s Size %d", IpVersion, Direction, Addr, Length)
	}
}

// Dump the current stats to a file
//
// We do this carefully writing to a .tmp file and renaming
func (a *Accounting) DumpFile() {
	fileLeaf := a.StartPeriod.Format(FileTimeFormat)
	filePath := path.Join(*LogDirectory, fileLeaf)
	fileTmp := filePath + ".tmp"
	fileCsv := filePath + ".csv"
	_, err := os.Lstat(fileCsv)
	if err == nil {
		log.Printf("Output file %q already exists", fileCsv)
		return
	}
	log.Printf("Dumping stats to %s", fileCsv)
	fd, err := os.Create(fileTmp)
	if err != nil {
		log.Printf("Failed to open stats file: %s", err)
		return
	}
	Ips := a.newMaps()
	err = Ips.Dump(fd, a.StartPeriod)
	err2 := fd.Close()
	if err != nil {
		log.Printf("Failed to write to stats file: %s", err)
		return
	}
	if err2 != nil {
		log.Printf("Failed to close stats file: %s", err)
		return
	}
	err = os.Rename(fileTmp, fileCsv)
	if err != nil {
		log.Printf("Failed to rename %q to %q: %s", fileTmp, fileCsv, err)
		return
	}
	log.Printf("Stats file %q written", fileCsv)
}

// Schedules file dumping dump for the end of the interval
func (a *Accounting) DumpStats() {
	for {
		now := time.Now()
		a.StartPeriod = FlooredTime(now)
		a.EndPeriod = a.StartPeriod.Add(*Interval)
		if *Debug {
			log.Printf("Next stats dump at %s", a.EndPeriod)
		}
		time.Sleep(a.EndPeriod.Sub(now))
		a.DumpFile()
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

	const Day = 24 * time.Hour

	// Check interval
	if *Interval < time.Second {
		log.Fatalf("Interval must be >= 1 Second")
	}
	if *Interval >= Day {
		if (*Interval % Day) != 0 {
			log.Fatalf("Interval %s isn't a whole number of days", *Interval)
		}
	} else {
		if (Day % *Interval) != 0 {
			log.Fatalf("Interval %s doesn't divide a day exactly", *Interval)
		}
	}

	// Make output directory
	err := os.MkdirAll(*LogDirectory, 0750)
	if err != nil {
		log.Fatalf("Failed to make log directory %q: %s", *LogDirectory, err)
	}

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

	// Setup profiling if desired
	if *CpuProfile != "" {
		log.Printf("Starting cpu profiler on %q", *CpuProfile)
		f, err := os.Create(*CpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	a := NewAccounting()
	var nflogs []*NfLog

	config := func(Group int, IpVersion byte, Direction IpDirection) {
		if Group > 0 {
			log.Printf("Monitoring NFLog multicast group %d for IPv%d %s", Group, IpVersion, Direction)
			nflog := NewNfLog(Group, IpVersion, Direction, a)
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
	go a.DumpStats()

	// Exit on keyboard interrrupt
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	signal.Notify(ch, syscall.SIGQUIT)
	s := <-ch
	log.Printf("%s received - shutting down", s)
	for _, nflog := range nflogs {
		nflog.Close()
	}
	log.Printf("Exit")
}
