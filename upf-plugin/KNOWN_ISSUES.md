Known Issues
============

This document lists the issues in UPG and also VPP issues that affect UPG usage.

Error handling in Sx procedures
-------------------------------

Currently, UPG doesn't do a very good job at error handling in the
PFCP server code.

TCP Proxy MSS Value
-----------------------

UPG employs a TCP proxy in case URL-based application detection is
used. The proxy uses [connection splicing][SPLICE] in order to improve
performance and reduce the load on the UPG instance. In order for a
proxied TCP connection to be spliced, it must MSS value greater than
or equal to that of the proxy. The proxy MSS value is set like this:
```
set upf proxy mss XXX
```
The current proxy settings can be checked like this:
```
show upf proxy
```

PFCP FIFO
---------

With large amounts of PFCP requests, UPG PFCP server's FIFO can be
sometimes overwhelmed. You can increase PFCP server's FIFO size like
this:
```
upf pfcp server set fifo-size 512
```
The default FIFO size is 64 KiB.

Important VPP Issues
====================

UDP MTU
-------

PFCP may produce large UDP datagrams sometimes. By default, VPP splits
datagrams over 1500 into multiple UDP datagrams, instead of using
proper IP fragmentation. In order to overcome this limitation, use
`udp { mtu XXX }` option in the VPP command line. The value of
"UDP MTU" doesn't need to reflect the MTU value of the interfaces, it
only controls that "UDP splitting" mechanism. If UDP MTU is greater
than the interface MTU from which the packet is sent, the packet will
be subject to IP fragmentation. Up to a certain VPP version, there was
a bug that was causing corruption of UDP datagrams of size greater
than 1908 bytes. The problem is now [fixed][UDPFIX] in VPP master, and
the fix is provided as a downstream patch under `vpp-patches/`.
   
IP Fragment Size limitation
---------------------------

VPP can't do buffer chaining for IP fragments it produces. This means
that if you don't increase VPP buffer size, VPP can't create IP
fragments of size > 2 KiB even if the interface has higher MTU value
(e.g. 9000). This may lead to hitting IP reassembly limits somewhere
down the line (e.g. VPP w/o UPG downstream patches has IP reassembly
limit of 3).

IP Reassembly Limit
-------------------

VPP has hardcoded IP reassembly limit of 3 fragments, which may not be
enough for large PFCP datagrams in some cases. Currently, UPG
overrides that with a downstream patch in `vpp-patches/`, setting it
to 8. At some point, we'll try to make this limit configurable via
binary API and CLI in VPP.

Heap size
---------

VPP can't expand its main heap beyond the initially specified size,
which defaults to 1 GiB. This may not be always enough for UPG, for
example, some of E2E tests don't pass with 1 GiB heap limit (it's now
increased in UPG E2E tests). It's advisable to set 2 GiB main heap
size.

[SPLICE]: http://www.cs.kent.edu/~javed/DL/web/p146-spatscheck.pdf
[UDPFIX]: https://gerrit.fd.io/r/c/vpp/+/31647
