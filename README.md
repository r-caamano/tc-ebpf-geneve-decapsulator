# Intro:

  This is a project to develop an ebpf program that 
  utilizes tc-bpf to redirect ingress ipv4 udp flows toward specific
  dynamically created sockets used by openziti edge-routers.

  prereqs: Ubuntu 22.04 server

           sudo apt update

           sudo apt upgrade

           sudo reboot

           sudo apt install -y gcc clang libc6-dev-i386 libbpfcc-dev libbpf-dev

  compile:

        clang -g -O2 -Wall -Wextra -target bpf -c -o redirect_udp.o redirect_udp.c
  
  attach:
        
        sudo tc qdisc add dev <interface name>  clsact

        sudo tc filter add dev <interface name> ingress bpf da obj redirect_udp.o sec sk_udp_redirect

  detach:

        sudo tc qdisc del dev <interface name>  clsact
