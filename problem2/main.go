package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const processNameLen = 16

type processPortConfig struct {
	Port        uint32
	ProcessName [processNameLen]byte
}

func main() {
	cgroup := flag.String("cgroup", "", "cgroup v2 directory to enforce")
	process := flag.String("process", "myprocess", "process comm name to restrict (max 15 bytes)")
	port := flag.Uint("port", 4040, "allowed TCP destination port (1-65535)")
	flag.Parse()

	if *cgroup == "" {
		log.Fatal("-cgroup is required")
	}
	if *port == 0 || *port > 65535 {
		log.Fatal("port must be between 1 and 65535")
	}
	if len(*process) == 0 || len(*process) > processNameLen-1 {
		log.Fatal("process name must be 1-15 bytes")
	}
	if info, err := os.Stat(*cgroup); err != nil || !info.IsDir() {
		log.Fatalf("cgroup directory %s: %s", *cgroup, err)
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

	cfg := coll.Maps["cfg_map"]
	if cfg == nil {
		log.Fatal("map cfg_map not found")
	}

	value := processPortConfig{Port: uint32(*port)}
	copy(value.ProcessName[:], *process)
	if err := cfg.Put(uint32(0), value); err != nil {
		log.Fatal(err)
	}

	pipe, err := os.Open("/sys/kernel/tracing/trace_pipe")
	if err != nil {
		log.Fatal("trace_pipe (run with sudo): ", err)
	}
	defer pipe.Close()

	prog4 := coll.Programs["allow_port_for_proc4"]
	prog6 := coll.Programs["allow_port_for_proc6"]

	lnk4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroup,
		Program: prog4,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lnk4.Close()

	lnk6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroup,
		Program: prog6,
		Attach:  ebpf.AttachCGroupInet6Connect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lnk6.Close()

	log.Printf("attached to %s, restricting %q to TCP port %d; streaming trace_pipe, ctrl+c to detach",
		*cgroup, *process, *port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("detaching")
		lnk4.Close()
		lnk6.Close()
		os.Exit(0)
	}()

	io.Copy(os.Stdout, pipe)
}