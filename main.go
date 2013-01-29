package main

import (
	"log"
	"runtime"
)

func accounting(Output chan *Packet) {
	for p := range Output {
		log.Printf("%s\n", p)
	}
}

// main
func main() {
	runtime.GOMAXPROCS(2 * runtime.NumCPU())

	Output := make(chan *Packet, 16384)
	nflog4 := NewNfLog(4, 4, IpDest, Output)
	go nflog4.Loop()
	nflog5 := NewNfLog(5, 4, IpSource, Output)
	go nflog5.Loop()
	nflog6 := NewNfLog(6, 6, IpDest, Output)
	go nflog6.Loop()
	nflog7 := NewNfLog(7, 6, IpSource, Output)
	go nflog7.Loop()

	// Loop forever accounting stuff
	accounting(Output)

}
