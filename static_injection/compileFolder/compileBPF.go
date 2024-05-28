package main

import (
    "log"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Allow the current process to lock memory for eBPF resources
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to set rlimit: %v", err)
    }

    // Load the precompiled eBPF program
    prog, err := ebpf.LoadObject("drop_tcp_port_4040.o")
    if err != nil {
        log.Fatalf("Failed to load eBPF object: %v", err)
    }
    defer prog.Close()

    // Load XDP program section
    xdpProgram := prog.Programs["drop_tcp_4040"]
    if xdpProgram == nil {
        log.Fatalf("Failed to find XDP program")
    }

    // Attach the program to the network interface (change "eth0" to your interface)
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
