## Statement 1 : Drop TCP packets destined to a praticular port

Step 1 : ebpf to elf objects

Step 1' : ebpf and xdp progams loaded to kernel

Step 1'' : validation of packets.

Step 2 : droppin of packets

### Steps for compilation
1. `clang -O2 -target bpf -c drop_tcp_port.c -o drop_tcp_port_4040.o`
2. `go build -o drop-tcp-port`
3. `sudo ./drop-tcp-port`

For the dynamic injection : we can load the port into port map which can be acessed by bpf program from the kernal space.

## Statement 3 Explain the code :
```
cnp := make(chan func(), 10)
for i := 0; i < 4; i++ {
go func() {
for f := range cnp {
f()
}
}()
}
cnp <- func() {
fmt.Println("HERE1")
}
fmt.Println("Hello")
```
1. The program starts 4 simulataneous go-routines which in turn listens to a channel names cnp , next a function func() is sent to the channel
   then the programs end with printing "hello" without printing "here1".
2. These can be used to trigger network calls that wait for a specific event to be triggered so that they can act upon . Go channels
    provide a very efficient way of managing message query without the need for external tools like RabbitMQ.
3. It creates simultaneous 4 go routines .
4. It is used to make buffered channel with buffer capacity = 10.
5. "Here1" didn't get printed because the program along with the go routines terminated intantly and function is sent to the channel . To resolve this , we can use sync.WaitGroup for the go routines which can prevent the program from terminating before all the operation have completed.
