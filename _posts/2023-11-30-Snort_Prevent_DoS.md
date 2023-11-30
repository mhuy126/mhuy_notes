---
layout: post
title: Snort Detect + Prevent DoS/DDoS
date: 2023-11-30 14:40:00 +0700
tags: [snort, dos/ddos]
toc: true
---

<p class="message">Demo using Snort to prevent the DoS/DDoS attack from Slowloris</p>

## Overview

### Attack Machine:

- OS: Kali Linux 2023
- Tool usage: [slowloris](https://github.com/gkbrk/slowloris)
- IP Address: 192.168.55.141 (NAT)

### Target Machine:

- OS: Ubuntu 20.04
- Server: Nginx 1.18 (localhost)
- Port 80
- IP Address: 192.168.55.143 (NAT)

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled.png)

## Prerequisite for Snort Configuration

Already installed Snort:

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%201.png)

Have 2 Network Interfaces and one of them was set as [promiscuous mode](https://www.thegeekdiary.com/how-to-configure-interface-in-promiscuous-mode-in-centos-rhel/): 

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%202.png)

## Perform DoS Attack

Using Kali Linux (Attack Machine) within `slowloris.py` tool:

```
python3 DoS_Attack/slowloris/slowloris.py -p 80 -s 1000 -v 192.168.55.143
```

Execute the command multiple times on multiple terminals:

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%203.png)

<aside>
💡 **Slowloris** is not a category of attack but is instead a specific attack tool designed to allow a single machine to take down a server without using a lot of bandwidth. Therefore, in real-life attack, it requires more than 1 machine to perform successfully within this tool.

</aside>

Observe the target http service and verify that it was taken down:

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%204.png)

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%205.png)

## Implement Snort to mitigate DoS/DDoS

I add a custom rule from this [source](https://raw.githubusercontent.com/maj0rmil4d/snort-ddos-mitigation/main/dos.rules) to detect the DoS/DDoS traffic. Then I modify it at 2 points:

- Replace the `!$HOME_NET` → `$EXTERNAL_NET`: to meet the configuration of the current version of Snort (2.9.7.0)
    
    ```
    sudo sed -i "s\!$HOME_NET\$EXTERNAL_NET\g" /etc/snort/rules/dos.rules
    ```
    
- Replace the `alert` action → `drop` action: to **DROP** the DoS/DDoS traffic when using the [inline mode of Snort](https://sublimerobots.com/2016/02/snort-ips-inline-mode-on-ubuntu/) instead of only **reporting** and **logging** the network traffic.
    
    ```
    sudo sed -i "s\alert\drop\g" /etc/snort/rules/dos.rules
    ```
    

The final rules would be like this:

```
#DOS ATTACK DETECTION
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: S; msg:"Possible SYN DoS"; flow: stateless; threshold: type both, track by_dst, count 1000, seconds 3; sid:10002;rev:1;)
#drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: A; msg:"Possible ACK DoS"; flow: stateless; threshold: type both, track by_dst, count 1000, seconds 3; sid:10001;rev:1;)
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: R; msg:"Possible RST DoS"; flow: stateless; threshold: type both, track by_dst, count 1000, seconds 3; sid:10003;rev:1;)
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: F; msg:"Possible FIN DoS"; flow: stateless; threshold: type both, track by_dst, count 1000, seconds 3; sid:10004;rev:1;)
drop udp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible UDP DoS"; flow: stateless; threshold: type both, track by_dst, count 1000, seconds 3; sid:10005;rev:1;)
drop icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible ICMP DoS"; threshold: type both, track by_dst, count 250, seconds 3; sid:10006;rev:1;)

#DDOS ATTACK DETECTION
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: S; msg:"Possible SYN DDoS"; flow: stateless; threshold: type both, track by_dst, count 100000, seconds 10; sid:100002;rev:1;)
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: A; msg:"Possible ACK DDoS"; flow: stateless; threshold: type both, track by_dst, count 100000, seconds 10; sid:100001;rev:1;)
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: R; msg:"Possible RST DDoS"; flow: stateless; threshold: type both, track by_dst, count 100000, seconds 10; sid:100003;rev:1;)
drop tcp $EXTERNAL_NET any -> $HOME_NET any (flags: F; msg:"Possible FIN DDoS"; flow: stateless; threshold: type both, track by_dst, count 100000, seconds 10; sid:100004;rev:1;)
drop udp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible UDP DDoS"; flow: stateless; threshold: type both, track by_dst, count 100000, seconds 10; sid:100005;rev:1;)
drop icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible ICMP DDoS"; threshold: type both, track by_dst, count 100000, seconds 10; sid:100006;rev:1;)

#PING OF DEATH DETECTION
drop icmp any any -> $HOME_NET any (msg:"Possible Ping of Death"; dsize: > 10000; sid:555555;rev:1;)
```

Add the new set of rules to the default snort configuration which is `snort.conf` file by appending this line at the end of the file:

```
include $RULE_PATH/dos.rules
```

Before implementing **Snort** with the new rules set, we must verify if that rules are validated:

```
sudo snort -c /etc/snort/snort.conf -T
```

And the result should be:

```
[--snipped--]

Rule application order: activation->dynamic->pass->drop->sdrop->reject->alert->log
Verifying Preprocessor Configurations!

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Snort successfully validated the configuration!
Snort exiting
```

Now the final step:

```
sudo snort -c /etc/snort/snort.conf -Q --daq afpacket -i ens33:ens38 -A console
```

- `-Q --daq afpacket`: active the inline mode
- `-i ens33:ens38`: indicate 2 network interfaces
- `-A console`: Apply [alert mode](https://linuxhint.com/snort_alerts/) as showing the output result on terminal

> **************************You can replace the `console` option with another to log the result into log files*
> 

Reload the page and observe the process handling by the Snort

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%206.png)

```
[--snipped--]
11/30-14:00:10.862149  [Drop] [**] [1:10003:1] Possible RST DoS [**] [Priority: 0] 
{TCP} 192.168.55.141:59388 -> 192.168.55.143:80
11/30-14:00:12.857772  [Drop] [**] [1:10003:1] Possible RST DoS [**] [Priority: 0] 
{TCP} 192.168.55.143:80 -> 192.168.55.141:40922
11/30-14:00:15.136646  [Drop] [**] [1:10003:1] Possible RST DoS [**] [Priority: 0] 
{TCP} 192.168.55.143:80 -> 192.168.55.141:48284
[--snipped--]
```

As you can see, **Snort** has dropped most of the *possible RST DoS* packets - which damage our server application (HTTP/HTTPS Service) - and covered the availability of the service.

## Import Notes

Within **Slowloris** is a tool designed as the low and slow attacks type, even the attacker has stopped the execution of `slowloris.py` (the attack binary file), the attack process still keeps going on:

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%207.png)

![Untitled](assets/Snort%20Detect%20+%20Prevent%20DoS%20DDoS/Untitled%208.png)

Accordingly, make sure the IPS - Intrusion Prevention System - is always activate and carefully maintained