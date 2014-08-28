package main

// FIXME write some stats every now and again - packets per second etc

// FIXME detect overflows?

// FIXME write dt in the file?

// FIXME don't dump stats file if empty?

// FIXME have a max entries parameter
// - dump the stats if get beyond that many entries?
// - or just refuse to add any more?
// - or add to 0.0.0.0 entry?

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
	FileTimeFormat = "2006-01-02-150405"
	// Number of packets to keep in the AddPackets Queue
	AddPacketsQueueSize = 8
)

// Globals
var (
	// Flags
	IPv4SourceGroup  = flag.Int("ip4-src-group", 0, "NFLog Group to read IPv4 packets and account the source address")
	IPv4DestGroup    = flag.Int("ip4-dst-group", 0, "NFLog Group to read IPv4 packets and account the destination address")
	IPv4PrefixLength = flag.Int("ip4-prefix-length", 32, "Size of the IPv4 prefix to account to, default is /32")
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
type HalfIpStats struct {
	Bytes   int64
	Packets int64
}

// Collect info about a single IP (or range)
type IpStats struct {
	Source HalfIpStats
	Dest   HalfIpStats
}

// Accounting for IP addresses
//
// The key is the net.IP which is a []byte converted to a string so it
// can be used as a hash key
type IpMap map[string]*IpStats

// Dump the IpMap to the output as a CSV
func (Ips IpMap) Dump(w io.Writer, when time.Time) error {
	wb := bufio.NewWriter(w)
	whenString := when.Format(CsvTimeFormat)
	_, err := fmt.Fprintf(wb, "Time,IP,SourceBytes,SourcePackets,DestBytes,DestPackets\n")
	if err != nil {
		return err
	}
	for key, stat := range Ips {
		ip := net.IP(key)
		_, err := fmt.Fprintf(wb, "%s,%s,%d,%d,%d,%d\n", whenString, ip, stat.Source.Bytes, stat.Source.Packets, stat.Dest.Bytes, stat.Dest.Packets)
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

// AddPacket holds the info about one packet
//
// Addr is a net.IP which is a []byte converted into a string This
// won't be a nice UTF-8 string but will preserve the bytes and can be
// used as a hash key
type AddPacket struct {
	Direction IpDirection
	Addr      string
	Length    int
}

// Accounting
type Accounting struct {
	StartPeriod       time.Time
	EndPeriod         time.Time
	Ips               IpMap
	engineWg          sync.WaitGroup
	dumpStatsWg       sync.WaitGroup
	engineStop        chan struct{}
	dumpStatsStop     chan struct{}
	processAddPackets chan []AddPacket
	returnAddPackets  chan []AddPacket
	flip              chan bool
	oldIps            chan IpMap
}

func NewAccounting() *Accounting {
	a := &Accounting{
		Ips:               make(IpMap, DefaultMapSize),
		engineStop:        make(chan struct{}),
		dumpStatsStop:     make(chan struct{}),
		processAddPackets: make(chan []AddPacket, AddPacketsQueueSize),
		returnAddPackets:  make(chan []AddPacket, AddPacketsQueueSize),
		flip:              make(chan bool, 1),
		oldIps:            make(chan IpMap, 1),
	}

	// Make some buffers
	for i := 0; i < AddPacketsQueueSize; i++ {
		a.returnAddPackets <- make([]AddPacket, 0, 128)
	}

	return a
}

// Make a new map returning the old one
func (a *Accounting) newMaps() IpMap {
	a.flip <- true
	return <-a.oldIps
}

// Account a single packet in a thread safe way
func (a *Accounting) Packet(Direction IpDirection, Addr string, Length int) {
	stat := a.Ips[Addr]
	if stat == nil {
		stat = &IpStats{}
		a.Ips[Addr] = stat
	}
	if Direction == IpSource {
		stat.Source.Bytes += int64(Length)
		stat.Source.Packets += 1
	} else {
		stat.Dest.Bytes += int64(Length)
		stat.Dest.Packets += 1
	}
	if *Debug {
		log.Printf("IP message %s Addr %s Size %d", Direction, net.IP(Addr), Length)
	}
}

// Accounting engine to account packets
//
// It has sole control over the Ips map which means that no locking is
// required
func (a *Accounting) Engine() {
	defer a.engineWg.Done()
	for {
		select {
		// Process a bunch of packets
		case ps := <-a.processAddPackets:
			for _, p := range ps {
				a.Packet(p.Direction, p.Addr, p.Length)
			}
			a.returnAddPackets <- ps

		// Flip the map
		case <-a.flip:
			a.oldIps <- a.Ips
			a.Ips = make(IpMap, DefaultMapSize)

		// Stop the engine
		case <-a.engineStop:
			if *Debug {
				log.Printf("Engine stop")
			}
			return
		}
	}
}

// Dump the current stats to a file
//
// We do this carefully writing to a .tmp file and renaming
func (a *Accounting) DumpFile() {
	fileLeaf := a.StartPeriod.Format(FileTimeFormat) + "_" + a.EndPeriod.Format(FileTimeFormat)
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
	defer a.dumpStatsWg.Done()
	a.StartPeriod = time.Now()
	a.EndPeriod = FlooredTime(a.StartPeriod).Add(*Interval)
	for {
		if *Debug {
			log.Printf("Next stats dump at %s", a.EndPeriod)
		}
		select {
		case <-time.After(a.EndPeriod.Sub(time.Now())):
		case <-a.dumpStatsStop:
			if *Debug {
				log.Printf("DumpStats stop")
			}
			a.EndPeriod = time.Now()
			a.DumpFile()
			return
		}
		a.DumpFile()
		a.StartPeriod = a.EndPeriod
		a.EndPeriod = a.StartPeriod.Add(*Interval)
	}
}

// Starts the accounting
func (a *Accounting) Start() {
	log.Printf("Starting accounting")
	a.engineWg.Add(1)
	go a.Engine()
	a.dumpStatsWg.Add(1)
	go a.DumpStats()
	log.Printf("Started accounting")
}

// Stops the accounting saving the stats so far
func (a *Accounting) Stop() {
	log.Printf("Stopping accounting")
	close(a.dumpStatsStop)
	if *Debug {
		log.Printf("Wait for dump stats stop")
	}
	a.dumpStatsWg.Wait()
	close(a.engineStop)
	if *Debug {
		log.Printf("Wait for engine stop")
	}
	a.engineWg.Wait()
	log.Printf("Stopped accounting")
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
	config := func(Group int, IpVersion byte, Direction IpDirection, MaskBits int) {
		if Group > 0 {
			log.Printf("Monitoring NFLog multicast group %d for IPv%d %s mask /%d", Group, IpVersion, Direction, MaskBits)
			NewNfLog(Group, IpVersion, Direction, MaskBits, a)
		}
	}

	config(*IPv4DestGroup, 4, IpDest, *IPv4PrefixLength)
	config(*IPv4SourceGroup, 4, IpSource, *IPv4PrefixLength)
	config(*IPv6DestGroup, 6, IpDest, *IPv6PrefixLength)
	config(*IPv6SourceGroup, 6, IpSource, *IPv6PrefixLength)

	if nflogs.Count() == 0 {
		log.Fatal("Not monitoring any groups - exiting")
	}

	// Loop forever accounting stuff
	a.Start()

	// Exit neatly on interrupt
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	signal.Notify(ch, syscall.SIGQUIT)
	s := <-ch
	log.Printf("%s received - shutting down", s)
	a.Stop()
	nflogs.Stop()
	log.Printf("Exit")
}
