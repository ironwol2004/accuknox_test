package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP to")
	port := flag.Uint("port", 4040, "TCP destination port to drop (1-65535)")
	flag.Parse()

	if *iface == "" {
		log.Fatal("-iface is required")
	}
	if *port == 0 || *port > 65535 {
		log.Fatal("port must be between 1 and 65535")
	}

	dev, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("interface %s: %s", *iface, err)
	}

	spec, err := ebpf.LoadCollectionSpec("eBPF.o")
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	cfg := coll.Maps["port_config_map"]
	if cfg == nil {
		log.Fatal("map port_config_map not found")
	}
	if err := cfg.Put(uint32(0), uint32(*port)); err != nil {
		log.Fatal(err)
	}

	pipe, err := os.Open("/sys/kernel/tracing/trace_pipe")
	if err != nil {
		log.Fatal("trace_pipe (run with sudo): ", err)
	}
	defer pipe.Close()

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_drop_port"],
		Interface: dev.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lnk.Close()

	log.Printf("attached XDP to %s, dropping TCP port %d; streaming trace_pipe, ctrl+c to detach",
		*iface, *port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("detaching")
		lnk.Close()
		os.Exit(0)
	}()

	io.Copy(os.Stdout, pipe)
}
