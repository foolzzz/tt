## TT, The Tunnel
A lightwight, cross-platform, secure and functional tunnel protocol, or tool.

----
### Quick start
#### server

    tt server -k password                       # will listen on 0.0.0.0, ports range: 1024-65535

#### client

    tt client -s [server addr] -k password      # will listen for http/socks5 proxy connection on 127.0.0.1:1080

----
### Benchmark?
Laptop: i7-8550U(max 4GHz), 16GB LPDDR3 2133 RAM 
	
	# server run:
	tt server -k 1234 &; sudo nc -l -p 80 < /dev/zero

	# client run:
	tt client -s 127.0.0.1 -k 1234 &; curl -x socks5://127.0.0.1:1080 127.0.0.1 >>/dev/null

Result:

|| tt | ss-libev|
|----|----|----|
|```aes-256-gcm```| 300 ~ 350 MB/s | 350 ~ 400 MB/s |
|```chacha20-poly1305```| ≈ 200 MB/s | ≈ 300 MB/s |

----
### Roadmap / Aims
- [x] Port jumping
    - [x] dynamic port (HOTP)
    - [x] dynamic port lifetime (HOTP)
- [x] Random padding
    - [x] random data
    - [x] dynamic length of random data
- [ ] Replay attack proof
	- [ ] use port+counter as AEAD additional data
- [x] Underlying protocol
    - [x] TCP (PROXY mode & TUN mode)
    - [x] UDP (TUN mode)
    - [ ] TCP fastopen
- [x] Proxy & tunnels 
    - [x] http proxy
    - [x] socks5 proxy(only CONNECT command suppported)
    - [x] TUN support (for Linux
	- [x] UTUN support (for MacOS
	- [ ] [WinTUN](https://www.wintun.net/) support (for Windows
	- [x] forward packet based on system route
- [x] Encryption
    - [x] aes-256-gcm
    - [x] chacha20-poly1305
- [ ] Hook API 
    - [ ] encode/decode hook api (consider eBPF)
- [ ] Fake traffic
    - [ ] fake http/https server
    - [ ] fake http/https traffic from client
- [ ] Multiple servers (load balancer)
    - [ ] support multiple servers
	- [ ] balance-rr mode
	- [ ] active-backup mode

----
### Usage 
#### server
```
tt-server 1.0.0
TT, The Tunnel, server side

USAGE:
    tt server [FLAGS] [OPTIONS] --key <key>

FLAGS:
    -h, --help                        Prints help information
        --no-port-jump-on-tun-mode
    -V, --version                     Prints version information
    -v, --verbose
        --with-proxy

OPTIONS:
    -k, --key <key>
    -l, --listen <listen-addr>      [default: 0.0.0.0]
    -m, --methods <methods>         [default: chacha20-poly1305]
    -r, --port-range <range>        [default: 1024-65535]
        --tun-ip <tun-ip>
        --tun-mtu <tun-mtu>         [default: 1410]
        --tun-proto <tun-proto>     [default: UDP]
```

#### client
```
tt-client 1.0.0
TT, The Tunnel, client side

USAGE:
    tt client [FLAGS] [OPTIONS] --key <key> --server <server>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose

OPTIONS:
    -k, --key <key>
    -l, --listen <listen-addr>      [default: 127.0.0.1:1080]
    -m, --methods <methods>         [default: chacha20-poly1305]
    -r, --port-range <range>        [default: 1024-65535]
    -s, --server <server>
        --tun-ip <tun-ip>
        --tun-mtu <tun-mtu>         [default: 1410]
        --tun-proto <tun-proto>     [default: UDP]
```

----
#### About MTU problem:

* TUN mode on ```udp``` , set mtu like：
    * ```--tun-mtu = 1410 - [ 1500 - REAL_MTU ]```


* TUN mode on ```tcp``` , set mtu or [TCP MSS clamping](https://www.tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.cookbook.mtu-mss.html)
    * ```--tun-mtu = 1410 - [ 1500 - REAL_MTU ]```
    * ```iptables -t mangle -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu```
