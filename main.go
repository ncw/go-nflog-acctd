package main

// main
func main() {
	nflog := NewNfLog()
	nflog.Loop()
	nflog.Close()
}
