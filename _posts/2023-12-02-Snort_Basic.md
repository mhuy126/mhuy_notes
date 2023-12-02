---
layout: post
title: Snort Basic Usage
date: 2023-12-02 08:40:00 +0700
tags: [snort, manual, basic]
toc: true
---

<p class="message">Introduction to Snort Basic Usage</p>

## Check Version

```
$ snort -V
```

## Verify Configuration File

```
$ sudo snort -c <CONF-PATH> -T
```

- `-c`: identify the configuration file
- `-T`: test configuration

Example:

```
$ sudo snort -c /etc/snort/snort.conf -T

[--snipped--]

--== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

           Rules Engine: SF_SNORT_DETECTION_ENGINE  Version 2.4  <Build 1>
           Preprocessor Object: SF_POP  Version 1.0  <Build 1>
           Preprocessor Object: SF_SSH  Version 1.1  <Build 3>
           Preprocessor Object: SF_DNP3  Version 1.1  <Build 1>
           Preprocessor Object: SF_DNS  Version 1.1  <Build 4>
           Preprocessor Object: SF_GTP  Version 1.1  <Build 1>
           Preprocessor Object: SF_MODBUS  Version 1.1  <Build 1>
           Preprocessor Object: SF_SDF  Version 1.1  <Build 1>
           Preprocessor Object: SF_DCERPC2  Version 1.0  <Build 3>
           Preprocessor Object: SF_FTPTELNET  Version 1.2  <Build 13>
           Preprocessor Object: SF_REPUTATION  Version 1.1  <Build 1>
           Preprocessor Object: SF_SMTP  Version 1.1  <Build 9>
           Preprocessor Object: SF_IMAP  Version 1.0  <Build 1>
           Preprocessor Object: SF_SIP  Version 1.1  <Build 1>
           Preprocessor Object: SF_SSLPP  Version 1.1  <Build 4>

Snort successfully validated the configuration!
Snort exiting
```

## Sniffer Mode

| Parameter | Description |
| --- | --- |
| -v | Verbose. Display the TCP/IP output in the console. |
| -d | Display the packet data (payload). |
| -e | Display the link-layer (TCP/IP/UDP/ICMP) headers. |
| -X | Display the full packet details in HEX. |
| -i | This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff. |

Example usages

```bash
$ sudo snort -i eth0 # identify network interface 'eth0'
$ sudo snort -v # verbose mode
$ sudo snort -d # dump packet data
$ sudo snort -de # dump packet with link-layer header grabbing
$ sudo snort -X # Full packet dump
```

## Packet Logger Mode

| Parameter | Description |
| --- | --- |
| -l | Logger mode, target log and alert output directory. Default output folder is /var/log/snort
The default action is to dump as tcpdump format in /var/log/snort |
| -K ASCII | Log packets in ASCII format. |
| -r | Reading option, read the dumped logs in Snort. |
| -n | Specify the number of packets that will process/read. Snort will stop after reading the spec |

```bash
$ sudo snort -dev -l .
$ sudo snort -dev -K ASCII -l . # Will create folders with IP Address names
$ sudo snort -r <LOG-FILE> $ Read the Snort's log (snort.log.xxxx)
# Filtering with the binary log files
$ sudo snort -r logname.log -X
$ sudo snort -r logname.log icmp
$ sudo snort -r logname.log tcp
$ sudo snort -r logname.log "udp and port 53"
$ sudo snort -r logname.log -n 10
```

## IPS/IDS Mode

| Parameter | Description |
| --- | --- |
| -N | Disable logging. |
| -D | Background mode. |
| -A | Alert modes;
full: Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any mode, snort uses this mode.

fast:  Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers.
console: Provides fast style alerts on the console screen.
cmg: CMG style, basic header details with payload in hex and text format.
none: Disabling alerting. |

```bash
$ sudo snort -Q --daq afpacket -i eth0:eth1 -c /etc/snort/snort.conf -A full
```

### Alert Mode

- console: Provides fast style alerts on the console screen.
- cmg: Provides basic header details with payload in hex and text format.
- **full:** Full alert mode, providing all possible information about the alert.
- **fast:** Fast mode, shows the alert message, timestamp, source and destination ıp along with port numbers.
- **none:** Disabling alerting.

| Mode | Descriptions | Console Output |
| --- | --- | --- |
| console | Provides fast style alerts on the console screen. | Yes |
| cmg | Provides basic header details with payload in hex and text format. | Yes |
| full | Full alert mode, providing all possible information about the alert. | No |
| fast | Fast mode, shows the alert message, timestamp, source and destination IP along with port numbers. | No |
| none | Disabling alerting. | No |

## PCAP Investigation

| Parameter | Description |
| --- | --- |
| -r / --pcap-single= | Read a single pcap |
| --pcap-list="" | Read pcaps provided in command (space separated). |
| --pcap-show | Show pcap name on console during processing. |

```bash
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap
sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"
```

## Snort Rule Structure

By default, Snort on Ubuntu expects to find a number of different rule files which are not included in the community rules. You can easily comment out the unnecessary lines using the `sed` command underneath.

```
sudo sed -i 's/include $RULE_PATH/#include $RULE_PATH/' /etc/snort/snort.conf
```

### Overview

![Untitled](/mhuy_notes/assets/Snort%20-%20Basic%20image/Untitled.png)

**Rule Header** is essential.

<table>
<tbody>
  <tr>
    <td>Action<br></td>
    <td>There are several actions for rules. Make sure you understand the functionality and test it before creating rules for live systems. The most common actions are listed below.<br>alert: Generate an alert and log the packet.<br>log: Log the packet.<br>drop: Block and log the packet.<br>reject: Block the packet, log it and terminate the packet session. </td>
  </tr>
  <tr>
    <td>Protocol<br></td>
    <td>Protocol parameter identifies the type of the protocol that filtered for the rule.<br>Note that Snort2 supports only four protocols filters in the rules (IP, TCP, UDP and ICMP). However, you can detect the application flows using port numbers and options. For instance, if you want to detect FTP traffic, you cannot use the FTP keyword in the protocol field but filter the FTP traffic by investigating TCP traffic on port 21.</td>
  </tr>
</tbody>
</table>

### IP & Port Numbers

<table>
<thead>
  <tr>
    <td>IP Filtering</td>
    <td>alert icmp 192.168.1.56 any &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each ICMP packet originating from the 192.168.1.56 IP address.</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Filter an IP range<br></td>
    <td>alert icmp 192.168.1.0/24 any &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each ICMP packet originating from the 192.168.1.0/24 subnet.</td>
  </tr>
  <tr>
    <td>Filter multiple IP ranges<br></td>
    <td>alert icmp [192.168.1.0/24, 10.1.1.0/24] any &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each ICMP packet originating from the 192.168.1.0/24 and 10.1.1.0/24 subnets.</td>
  </tr>
  <tr>
    <td>Exclude IP addresses/ranges<br></td>
    <td>"negation operator" is used for excluding specific addresses and ports. Negation operator is indicated with "!"<br>alert icmp !192.168.1.0/24 any &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each ICMP packet not originating from the 192.168.1.0/24 subnet.</td>
  </tr>
  <tr>
    <td>Port Filtering</td>
    <td>alert tcp !192.168.1.0/24 21 &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each TCP packet originating from port 21.</td>
  </tr>
  <tr>
    <td>Exclude a specific port<br></td>
    <td>alert tcp !192.168.1.0/24 !21 &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each TCP packet not originating from port 21.</td>
  </tr>
  <tr>
    <td>Filter a port range (Type 1)<br></td>
    <td>alert tcp !192.168.1.0/24 1:1024 &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each TCP packet originating from ports between 1-1024.</td>
  </tr>
  <tr>
    <td>Filter a port range (Type 2)<br></td>
    <td>alert icmp any :1024 &lt;&gt; any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each TCP packet originating from ports less than or equal to 1024.</td>
  </tr>
  <tr>
    <td>Filter a port range (Type 3)<br></td>
    <td>alert icmp any 1024: &lt;&gt; any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each TCP packet originating from a source port higher than or equal to 1024.</td>
  </tr>
  <tr>
    <td>Filter a port range (Type 4)<br></td>
    <td>alert icmp any 80,1024: &lt;&gt; any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br>This rule will create alerts for each TCP packet originating from a source port 80 and higher than or equal to 1024.</td>
  </tr>
</tbody>
</table>

### Direct

The left side of the rule shows the source, and the right side shows the destination.

- **>** Source to destination flow.
- **<>** Bidirectional flow

<p class="message">
❗ Note that **there is no "<-" operator in Snort.**

</aside>

```bash
alert icmp any 80,1024: <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
```

## Rule Options

- General Rule Options - Fundamental rule options for Snort.
- Payload Rule Options - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
- Non-Payload Rule Options - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

### General Rule Options

<table>
<thead>
  <tr>
    <td>Msg</td>
    <td>The message field is a basic prompt and quick identifier of the rule. Once the rule is triggered, the message filed will appear in the console or log. Usually, the message part is a one-liner that summarises the event.<br></td>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Sid<br></td>
    <td>Snort rule IDs (SID) come with a pre-defined scope, and each rule must have a SID in a proper format. There are three different scopes for SIDs shown below.<br>&lt;100: Reserved rules<br>100-999,999: Rules came with the build.<br>&gt;=1,000,000: Rules created by user.<br>Briefly, the rules we will create should have sid greater than 100.000.000. Another important point is; SIDs should not overlap, and each id must be unique. </td>
  </tr>
  <tr>
    <td>Reference<br></td>
    <td>Each rule can have additional information or reference to explain the purpose of the rule or threat pattern. That could be a Common Vulnerabilities and Exposures (CVE) id or external information. Having references for the rules will always help analysts during the alert and incident investigation.<br></td>
  </tr>
  <tr>
    <td>Rev<br></td>
    <td>Snort rules can be modified and updated for performance and efficiency issues. Rev option help analysts to have the revision information of each rule. Therefore, it will be easy to understand rule improvements. Each rule has its unique rev number, and there is no auto-backup feature on the rule history. Analysts should keep the rule history themselves. Rev option is only an indicator of how many times the rule had revisions.<br>alert icmp any any &lt;&gt; any any (msg: "ICMP Packet Found"; sid: 100001; reference:cve,CVE-XXXX; rev:1;)</td>
  </tr>
</tbody>
</table>

### Payload Rule Options

<table>
<thead>
  <tr>
    <td>Content<br></td>
    <td>Payload data. It matches specific payload data by ASCII, HEX or both. It is possible to use this option multiple times in a single rule. However, the more you create specific pattern match features, the more it takes time to investigate a packet.<br>Following rules will create an alert for each HTTP packet containing the keyword "GET". This rule option is case sensitive!<br>ASCII mode - alert tcp any any &lt;&gt; any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)<br>HEX mode - alert tcp any any &lt;&gt; any 80  (msg: "GET Request Found"; content:"|47 45 54|"; sid: 100001; rev:1;)</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Nocase<br></td>
    <td>Disabling case sensitivity. Used for enhancing the content searches.<br>alert tcp any any &lt;&gt; any 80  (msg: "GET Request Found"; content:"GET"; nocase; sid: 100001; rev:1;)</td>
  </tr>
  <tr>
    <td>Fast_pattern<br></td>
    <td>Prioritise content search to speed up the payload search operation. By default, Snort uses the biggest content and evaluates it against the rules. "fast_pattern" option helps you select the initial packet match with the specific value for further investigation. This option always works case insensitive and can be used once per rule. Note that this option is required when using multiple "content" options. <br>The following rule has two content options, and the fast_pattern option tells to snort to use the first content option (in this case, "GET") for the initial packet match.<br><br>alert tcp any any &lt;&gt; any 80  (msg: "GET Request Found"; content:"GET"; fast_pattern; content:"www";  sid:100001; rev:1;)</td>
  </tr>
</tbody>
</table>

### Non-Payload Rule Options

<table>
<thead>
  <tr>
    <td>ID</td>
    <td>Filtering the IP id field.<br>alert tcp any any &lt;&gt; any any (msg: "ID TEST"; id:123456; sid: 100001; rev:1;)</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Flags<br></td>
    <td>Filtering the TCP flags.<br>F - FIN<br>S - SYN<br>R - RST<br>P - PSH<br>A - ACK<br>U - URG<br><br>alert tcp any any &lt;&gt; any any (msg: "FLAG TEST"; flags:S;  sid: 100001; rev:1;)</td>
  </tr>
  <tr>
    <td>Dsize<br></td>
    <td>Filtering the packet payload size.<br>dsize:min&lt;&gt;max;<br>dsize:&gt;100<br>dsize:&lt;100<br>alert ip any any &lt;&gt; any any (msg: "SEQ TEST"; dsize:100&lt;&gt;300;  sid: 100001; rev:1;)</td>
  </tr>
  <tr>
    <td>Sameip<br></td>
    <td>Filtering the source and destination IP addresses for duplication.<br>alert ip any any &lt;&gt; any any (msg: "SAME-IP TEST";  sameip; sid: 100001; rev:1;)</td>
  </tr>
</tbody>
</table>

<p class="message">
❗ Your created rules must be placed in `local.rules` file

</p>

## References

TryHackMe: [https://tryhackme.com/room/snort](https://tryhackme.com/room/snort)