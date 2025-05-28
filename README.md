# raw-tcp-segment

This was a weekend project to better understand networking and TCP/IP.

Usage: `sudo ./send_tcp <source_ip> <source_ip> <dest_ip> <dest_port> [data]`
Which will send a TCP-syn segment with the corresponding IP and ports. 

To build: `gcc send_tcp.c -o send_tcp -Wall`

This builds the IP header (RFC 791) and TCP header (RFC 793) from scratch as required through the use of `SOCK_RAW` and `IPPROTO_RAW` sockets.

## Future work:
Implement a full TCP three way handshake.
Implement TCP options. 
