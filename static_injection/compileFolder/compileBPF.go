package main

import (
    "log"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // allocating memory for the program
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to set rlimit: %v", err)
    }
    // loading the precompiled ebpf program
    prog, err := ebpf.LoadObject("drop_tcp_port_4040.o")
    if err != nil {
        log.Fatalf("Failed to load eBPF object: %v", err)
    }
    defer prog.Close()

    // Now loading the ebpf program section
    xdpProgram := prog.Programs["drop_tcp_4040"]
    if xdpProgram == nil {
        log.Fatalf("Failed to find XDP program")
    }

    // attaching the network to preferred interface , for my case it is eth0
    iface := "eth0"
    link, err := link.AttachXDP(link.XDPOptions{
        Program:   xdpProgram,
        Interface: iface,
    })
    if err != nil {
        log.Fatalf("Failed to attach XDP program: %v", err)
    }
    defer link.Close()

    log.Printf("XDP program successfully attached to interface %s", iface)

    // Keep the program running
    select {}
}
