# Intro:

  This is a project to develop an ebpf program that 
  utilizes tc-bpf to redirect ingress ipv4 udp flows toward specific
  dynamically created sockets used by openziti edge-routers.
  Note: For this to work the ziti-router code had to be modified to not insert
        an ip tables tproxy rule for the service defined for SIP.

  prereqs: Ubuntu 22.04 server

           sudo apt update

           sudo apt upgrade

           sudo reboot

           sudo apt install -y gcc clang libc6-dev-i386 libbpfcc-dev libbpf-dev

  compile:

        clang -O2 -Wall -Wextra -target bpf -c -o redirect_udp.o redirect_udp.c
        clang -O2 -Wall -Wextra -o map_update map_update.c
        clang -O2 -Wall -Wextra -o map_delete_elem map_delete_elem.c 
  
  attach:
        
        sudo tc qdisc add dev <interface name>  clsact

        sudo tc filter add dev <interface name> ingress bpf da obj redirect_udp.o sec sk_udp_redirect

  detach:

        sudo tc qdisc del dev <interface name>  clsact

  Example: Insert map entry to direct SIP traffic destined for 172.16.240.0/24

        Usage: ./map_update <hex_dest_prefix ex. 0a000001> <dst_port> <src_port> <tproxy_port>
        sudo ./map_update 0xac10f000 5060 5060 59181 
  
  Example: Remove prevoius entry from map

        Usage: ./map_delete_elem <hex_dest_prefix ex. 0a000001>
        sudo ./map_delete_elem 0xac10f000 
