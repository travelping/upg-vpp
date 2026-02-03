GTP-U User Plane Function (UPF) based on VPP
============================================

Note: Upstream VPP README can be found [here](/README-VPP.md)

The UPF plugins implements a GTP-U user plane based on [3GPP TS 23.214][TS23214] and
[3GPP TS 29.244][TS29244] Release 15/16.

Current State
-------------

This UPF implementation is used in production in conjuction with [erGW][erGW] as
GGSN/PGW in multiple installation in several telecom operators (Tier 1 and smaller).

Working features
----------------

* Multithreading support
* IPv6 for inner and outer headers
* PFCP protocol
  * En/Decoding of most IEs
  * Heartbeat
  * Node related messages
  * Session related messages
  * SMF Set Id -- With one PFCP association per SMF and UPF (5.22.3 in [3GPP TS 29.244][TS29244])
* Uplink and Downlink Packet Detection Rules (PDR) -- (some parts)
  * URI regexp matching
* Forward Action Rules (FAR) -- (some parts)
  * HTTP Redirect
  * NAT pools
  * Forwarding policy
  * IPFix policy
  * End Marker
* Usage Reporting Rules (URR) -- (some triggers)
  * Volume/Time Quotas/Thresholds/Measurements
  * Monitoring Time Split
  * Multiple URRs per PDR
  * Linked Usage Reports
  * PFCP Session Reports
* QoS Enforcement Rule (QER) -- (only maximum bitrate)

No yet working
--------------

* Buffer Action Rules (BAR)
* FAR action with destination LI are not implemented
* Ethernet bearer support

[erGW]: https://github.com/travelping/ergw
[TS23214]: http://www.3gpp.org/ftp/Specs/html-info/23214.htm
[TS29244]: http://www.3gpp.org/ftp/Specs/html-info/29244.htm
