# Branching Decision Simulations


Presents a realistic investigative scenario with genuine decision points. Unlike a checklist, the paths here reflect trade offs choosing one analytical approach first means seeing certain evidence before other evidence, which shapes the hypotheses you carry forward.

Work through each decision actively. Resist reading ahead. At each decision point, commit to a choice before you read what that path reveals. The goal isn't to find the "right" answer; it's to understand *why* different starting points surface different evidence, so you develop the judgment to know which question to ask first in an actual investigation.

Instructor notes are embedded throughout for facilitators running these scenarios in training contexts.

---

# Playbook 1: Data Exfiltration

## Investigative Frame

**Trigger:** Your DLP system fired an alert at 23:47 on a Thursday: `HIGH_VOLUME_OUTBOUND` from `WKSTN-ACCT-014` (10.10.3.14), an accountant's workstation. The alert threshold is 200MB outbound in a 30-minute window. No user was logged into the workstation at 23:47 according to the authentication logs.

**What you know:** WKSTN-ACCT-014 runs Windows, uses the corporate proxy at 10.10.1.5 for web traffic, accesses an accounting application at 10.10.6.30, and connects to network file shares at 10.10.8.0/24. The user is on vacation.

**What you need to determine:** What was transferred, where did it go, how did it leave, and is this an isolated event or part of a larger pattern?

**The capture:** You have a pcap spanning 23:00 to 01:00—two hours surrounding the alert window. It's approximately 400MB.

**Your first move matters.** Three approaches are reasonable. Choose before reading further.

---

## DECISION POINT 1: Your First Filter

```
┌─────────────────────────────────────────────────────────────────┐
│  What do you filter on first?                                   │
│                                                                 │
│  A → External IP traffic (bypass baseline, find the           │
│      destination immediately)                                   │
│                                                                 │
│  B → Protocol-based filter (identify what kind of transfer    │
│      this was before worrying about destination)               │
│                                                                 │
│  C → Time window filter (understand the shape of the          │
│      traffic across the full capture before narrowing)         │
└─────────────────────────────────────────────────────────────────┘
```

---

### PATH A — External IP Traffic First

**Filter:**
```
ip.src == 10.10.3.14 && !(ip.dst == 10.10.0.0/16) && !(ip.dst == 192.168.0.0/16)
```

**What surfaces:** Every packet leaving WKSTN-ACCT-014 destined for an IP outside your internal address space. Because this host should proxy all web traffic through 10.10.1.5, any direct connection to an external IP is immediately anomalous—not a lead to pursue, but a confirmed deviation before you've looked at a single packet's content.

**What you should observe:** Two categories of traffic appear. First, a small volume of traffic to external Microsoft infrastructure (Windows Update, telemetry endpoints) recognizable by destination hostname if you've correlated DNS first, or by IP range if you know Microsoft's published ASN space. Second, a sustained connection to 198.51.100.77 on port 443 accounting for most of the alert volume. This second connection has no DNS precedent in the capture (the IP was not resolved by name from this host), meaning it was either hardcoded in the exfiltration tool or the DNS query occurred outside your capture window.

**Why this approach works well here:** For a DLP alert where volume is the trigger, getting to the anomalous destination quickly is efficient. The proxy architecture means any direct external connection is immediately suspicious you don't have to evaluate whether the destination is legitimate, because the mechanism of connection (bypassing the proxy) already isn't. You've found your primary lead in one filter.

**What this approach misses initially:** You don't yet know *what* protocol ran over that TLS connection, whether the host staged the data locally before transfer, or whether this was the first transfer or one of several. Path A gets you to the destination fastest but leaves protocol and staging evidence for subsequent investigation steps.

**How Path B would have differed:** Filtering by protocol first (HTTP, SMB, FTP) would have shown you how data moved before showing you where it went. In an exfiltration where the attacker used a protocol that blends with legitimate traffic HTTPS through the proxy, for instance Path B surfaces that blending. Here, because the exfiltration bypassed the proxy entirely, Path A is more direct. But in environments without proxy architecture, Path B often provides better initial signal.

**How Path C would have differed:** The time window approach gives you the shape of the attack across two hours you'd see whether the large transfer was preceded by smaller probe connections or followed by cleanup activity. Path C is most valuable when you suspect the DLP alert is capturing only part of a multi-stage operation. Here it would have shown you that activity began around 23:10, approximately 37 minutes before the DLP threshold was crossed, suggesting the transfer started slowly before accelerating.

> **Instructor Note:** Path A teaches the value of network architecture knowledge. An analyst who knows what baseline traffic looks like (proxy for web, no direct external connections from workstations) can use that architecture as a filter before constructing a Wireshark filter. The Wireshark filter is precise; the architecture knowledge is what makes it meaningful.

---

### DECISION POINT 2 (From Path A): Certificate and SNI Analysis

You've identified the primary transfer destination: 198.51.100.77:443. The connection is TLS. You can't read the content. What do you examine next?

```
┌─────────────────────────────────────────────────────────────────┐
│  How do you characterize the TLS connection?                    │
│                                                                 │
│  A1 → Inspect the certificate presented by the server          │
│       (issuer, validity, CN/SAN)                               │
│                                                                 │
│  A2 → Examine the Client Hello metadata (cipher suites,        │
│       extensions, SNI presence)                                │
│                                                                 │
│  A3 → Analyze transfer volume and directionality               │
│       (is this mostly outbound or a two-way exchange?)         │
└─────────────────────────────────────────────────────────────────┘
```

**Path A1 — Certificate Inspection:**

**Filter:**
```
tls.handshake.type == 11 && ip.src == 198.51.100.77
```

**What surfaces:** The Certificate message from the server. Expand `Transport Layer Security → TLSv1.3 Record Layer → Handshake Protocol → Certificate`. The certificate chain reveals the issuer (in this scenario, a Let's Encrypt certificate issued 6 days ago), the CN (a hostname with no obvious vendor association—something like `api.cloudstoredrive.net`), and a validity period of 90 days.

**What this tells you:** A 6-day-old Let's Encrypt certificate on a hostname that resolves to no recognizable service is consistent with adversarial infrastructure. Let's Encrypt is free, automated, and trusted making it the certificate authority of choice for attacker controlled servers that need to avoid TLS warnings. This is not definitive (many legitimate services also use Let's Encrypt), but combined with the proxy bypass and the off-hours transfer, it adds weight to the adversarial hypothesis.

Note the certificate fingerprint (SHA-256 hash visible in the dissector). Run this against certificate transparency logs (crt.sh) and threat intelligence platforms. If the certificate has been associated with known C2 infrastructure, the investigation's urgency immediately increases.

**Path A2 — Client Hello Analysis:**

**Filter:**
```
tls.handshake.type == 1 && ip.src == 10.10.3.14 && ip.dst == 198.51.100.77
```

**What surfaces:** The Client Hello from WKSTN-ACCT-014. Examine the cipher suite list: does it match what you'd expect from a Windows application using the system TLS stack (which would produce a characteristic Windows Schannel cipher suite list), or does it look like a non-OS TLS implementation? In this scenario, the cipher suite list is minimal three suites, no elliptic curve extensions—consistent with a custom TLS implementation embedded in exfiltration tooling rather than a standard application using the Windows TLS library.

Also note whether SNI is present. It's absent here, which is notable legitimate applications using TLS almost universally include SNI. A Client Hello without SNI from a Windows host is a meaningful anomaly.

**Path A3 — Directionality Analysis:**

**Filter:** (use Conversations view, not a display filter)

In Statistics → Conversations, locate the conversation with 198.51.100.77 and read the A→B (host to external) versus B→A (external to host) byte counts.

**What surfaces:** In this scenario, the host sent approximately 340MB to the external IP and received approximately 1.2MB back. The ratio is overwhelmingly outbound. This asymmetry is what exfiltration looks like at the flow level large outbound, minimal inbound. Compare this to the legitimate Microsoft traffic in the same capture: those flows show proportional exchange or are predominantly inbound (downloading updates).

> **Instructor Note:** Paths A1, A2, and A3 are not mutually exclusive a thorough investigator does all three. The pedagogical value of the branching is teaching analysts that each layer answers a different question: the certificate answers "whose infrastructure is this?", the Client Hello answers "what created this connection?", and the directionality answers "what happened in it?". Analysts who default to checking only the destination IP are missing two of these three dimensions.

---

### DECISION POINT 3: Pre-Transfer Activity

You've confirmed: 340MB of data left WKSTN-ACCT-014 to adversarial infrastructure over TLS. Now look backward. What happened before the transfer?

```
┌─────────────────────────────────────────────────────────────────┐
│  What pre-transfer activity do you investigate?                 │
│                                                                 │
│  A→I  → SMB traffic from this host (was data staged from      │
│          network shares before exfiltration?)                  │
│                                                                 │
│  A→II → DNS queries before the transfer window                │
│          (what did the host resolve, when?)                    │
│                                                                 │
│  A→III → All outbound connections in the hour before          │
│           the transfer (reconnaissance footprint?)            │
└─────────────────────────────────────────────────────────────────┘
```

**Path A→I — SMB Staging Investigation:**

**Filter:**
```
smb2 && ip.src == 10.10.3.14 && frame.time >= "2024-01-18 22:45:00"
```

**What surfaces:** A sequence of SMB2 READ operations from `10.10.8.45` (a file server) beginning at 23:10—37 minutes before the DLP alert threshold was crossed. The READ operations are accessing files in a path that, from the `smb2.filename` field, contains the string `accounting\Q4_2023`. The aggregate read volume from SMB aligns with the size of the subsequent TLS transfer: approximately 340MB of files were accessed from the file server and then transferred externally.

This confirms a two-stage operation: data was first pulled from network shares to the local host (or directly streamed), then pushed to the external destination. The file server access gives you a source data inventory—you can reconstruct which specific files were exfiltrated from the SMB READ log.

**Path A→II — DNS Analysis:**

**Filter:**
```
dns && ip.src == 10.10.3.14
```

Look specifically at the timeframe between 22:45 and 23:10. What does the query pattern look like? You'll find routine queries to internal `.corp` domains (normal background application behavior), followed by a single query for `api.cloudstoredrive.net` at 23:09—the hostname corresponding to the certificate you found on 198.51.100.77. The resolution occurs exactly 2 minutes before the SMB access begins, suggesting the malware checked in with its exfiltration endpoint before beginning data collection.

This sequence is operationally significant: the malware verified the destination was reachable *before* collecting data. This is a behavioral indicator of more sophisticated tooling versus simpler scripts that collect first and then attempt transfer regardless of destination availability.

**Path A→III — Reconnaissance Footprint:**

**Filter:**
```
ip.src == 10.10.3.14 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && \
frame.time <= "2024-01-18 23:10:00"
```

**What surfaces:** In the hour before the transfer, WKSTN-ACCT-014 generated SYN packets to several internal IPs it doesn't normally contact: 10.10.8.40, 10.10.8.45, 10.10.8.50, 10.10.8.55. This is a low speed scan of the file server subnet, apparently identifying which hosts have SMB open. The scan is slow four targets over approximately 15 minutes—which is consistent with deliberate attempts to avoid rate-based detection.

---

## Playbook 1 Complete — Reconstructed Narrative

Working through the evidence:

1. ~22:45: Malware activates on an unoccupied workstation
2. ~23:09: DNS query resolves the exfiltration endpoint
3. ~23:10: SMB reconnaissance across file server subnet identifies accessible shares
4. ~23:12: SMB READ operations pull Q4 accounting data from 10.10.8.45
5. ~23:47: DLP alert fires as cumulative outbound volume crosses 200MB threshold
6. ~00:01: Transfer completes; 340MB exfiltrated to adversarial infrastructure

What the packets don't tell you: how the host was initially compromised, whether the malware persists on disk, whether other hosts were similarly affected, and what the attacker did with the data. Packet analysis closes this chapter and opens the endpoint forensics chapter.

---
---

# Playbook 2: Lateral Movement

## Investigative Frame

**Trigger:** Your EDR generated an alert at 10:14: `CREDENTIAL_DUMP_ATTEMPT` on `WKSTN-IT-003` (10.10.1.30), a member of the IT support team. The EDR detected a process consistent with LSASS memory access. No immediate containment action was taken because your IR policy requires packet capture before isolation to preserve behavioral evidence.

**What you know:** WKSTN-IT-003 legitimately accesses systems throughout the network for support purposes—this makes its normal traffic profile broader than most workstations. It regularly connects to servers via RDP, accesses the help desk system at 10.10.2.15, and communicates with the domain controllers. The EDR alert suggests credentials were harvested from this host. Your concern is not the compromised workstation—it's where the adversary went with those credentials.

**What you need to determine:** Has lateral movement occurred from WKSTN-IT-003 using harvested credentials? Which systems were targeted? What level of access was achieved?

**The capture:** 90 minutes covering 10:00–11:30. The network is active during business hours, so there's legitimate traffic throughout.

---

## DECISION POINT 1: Lateral Movement Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│  Where do you start hunting for lateral movement?               │
│                                                                 │
│  A → Discovery traffic (ARP, NetBIOS, LDAP queries)            │
│      — find the reconnaissance before the movement             │
│                                                                 │
│  B → SMB and authentication traffic from this host             │
│      — look for credential use directly                        │
│                                                                 │
│  C → Kerberos traffic to and from the domain controllers       │
│      — credential reuse shows up in ticket requests            │
└─────────────────────────────────────────────────────────────────┘
```

---

### PATH A — Discovery Traffic First

**Filter:**
```
(arp || nbns || ldap) && ip.src == 10.10.1.30
```

**What surfaces:** Three types of activity emerge. First, normal ARP responses background traffic for maintaining the host's ARP cache, unremarkable. Second, LDAP queries to the domain controller at 10.10.1.10. Here the content matters: expand the LDAP search request and examine the `ldap.filter` field. You're looking for queries that enumerate user accounts, administrative groups, or computer objects reconnaissance activity that goes beyond what normal endpoint operation requires.

In this scenario, at 10:16—two minutes after the EDR alert—a series of LDAP queries appears with filters like `(objectClass=computer)` and `(memberOf=CN=Domain Admins,DC=corp,DC=local)`. These are programmatic domain enumeration queries, not user-initiated searches through ADUC. The timing tells the story: the adversary dumped credentials, then immediately queried AD to identify high-value targets.

**What this approach reveals:** The reconnaissance phase, including specifically what the adversary was mapping. If you can see what they were enumerating (domain admins, servers, specific OUs), you can infer what they were planning to target even before they tried to access those systems. This is the highest leverage starting point because it lets you get ahead of the movement rather than just documenting where it went.

**What it misses initially:** Discovery traffic doesn't show you which systems were actually accessed successfully. It's the reconnaissance; the exploitation follows. After Path A, you still need Path B or C to find the actual lateral movement.

**How Path B would have differed:** Going to SMB first gets you directly to authentication attempts and share access actual movement rather than reconnaissance. This is more efficient if reconnaissance already happened outside your capture window and the movement is in progress, but it misses the early-stage evidence that helps you understand the adversary's intent.

**How Path C would have differed:** Kerberos analysis is particularly powerful when the adversary is using harvested Kerberos tickets (pass-the-ticket) or forged tickets (golden/silver ticket attacks) rather than NTLM or cleartext credentials. If NTLM is being used for lateral movement, Kerberos filters won't find it. Path C is most valuable when you suspect privileged ticket abuse specifically.

> **Instructor Note:** Path A teaches investigators to look for the decision-making trail before the action. The reconnaissance phase reveals what the adversary *valued* and *planned*—information that shapes your entire containment strategy. An analyst who jumps immediately to authentication evidence may find the lateral movement but miss the targeting intelligence that tells them *which systems are at highest risk* from this actor.

---

### PATH B — SMB Authentication Traffic

**Filter:**
```
smb2 && ip.src == 10.10.1.30 && smb2.cmd == 0x01
```

`smb2.cmd == 0x01` is the Session Setup command the authentication step of every SMB connection. This filter shows every system WKSTN-IT-003 authenticated to over SMB during the capture window, which in an IT support context might be many systems—this is where the "broad legitimate profile" caveat from the premise matters.

**What surfaces:** A longer list than you'd see from a regular workstation. Your job is to normalize this list against the IT support baseline. If you have historical NetFlow or log data for this host, which of these authentication destinations are new during today's capture? In this scenario, the destinations include a mix of known-good servers (the help desk system, standard file shares) and three systems that don't appear in the host's authentication history: `SRV-PAY-01` (10.10.9.10), `SRV-HR-DB` (10.10.9.11), and `SRV-EXE-01` (10.10.9.5).

For each of these three anomalous destinations, trace the full SMB exchange. Did the Session Setup complete successfully (server returned STATUS_SUCCESS), or was it rejected (STATUS_LOGON_FAILURE)? The SMB2 Session Setup Response contains `smb2.nt_status`—a successful authentication returns `0x00000000`.

**Filter for successful authentication only:**
```
smb2 && smb2.cmd == 0x01 && smb2.nt_status == 0x00000000 && \
(ip.dst == 10.10.9.10 || ip.dst == 10.10.9.11 || ip.dst == 10.10.9.5)
```

**What this tells you:** The adversary authenticated successfully to all three anomalous destinations. Now trace what they did after authenticating: look for TREE_CONNECT requests showing which shares were accessed, IPC$ connections indicating administrative remote access, and any subsequent CREATE or READ operations on specific files.

---

### DECISION POINT 2 (From Path B): Characterizing the Access

The adversary authenticated to three high-value servers. What do you examine next?

```
┌─────────────────────────────────────────────────────────────────┐
│  The adversary is authenticated to three servers.               │
│  What do you examine to understand what they did?              │
│                                                                 │
│  B1 → File operations (what was READ or WRITE?)                │
│                                                                 │
│  B2 → IPC$ and DCERPC traffic (were remote services           │
│        or processes invoked?)                                   │
│                                                                 │
│  B3 → What authentication mechanism was used                   │
│        (NTLM vs. Kerberos—this indicates the credential type) │
└─────────────────────────────────────────────────────────────────┘
```

**Path B1 — File Operation Analysis:**

**Filter:**
```
smb2 && (ip.src == 10.10.1.30 || ip.dst == 10.10.1.30) && \
smb2.cmd == 0x05 && (ip.addr == 10.10.9.10 || ip.addr == 10.10.9.11)
```

`smb2.cmd == 0x05` is the CREATE command (file open/create). This shows every file or directory the adversary opened on these servers. Examine the `smb2.filename` fields. On `SRV-PAY-01`, the adversary accessed `ADMIN$` (administrative share) and then specific files within a path consistent with the payroll application. On `SRV-HR-DB`, they accessed `\\SRV-HR-DB\Data$\Employee_Records`.

**Path B2 — Remote Execution Investigation:**

**Filter:**
```
dcerpc && (ip.src == 10.10.1.30 || ip.dst == 10.10.1.30) && \
(ip.addr == 10.10.9.5 || ip.addr == 10.10.9.10)
```

**What surfaces:** DCERPC calls over SMB/IPC$. Examine the `dcerpc.cn_bind_if` field (the interface UUID being bound) on each call. The UUID `367abb81-9844-35f1-ad32-98f038001003` corresponds to SVCCTL (Service Control Manager) an adversary using PsExec-style execution will bind to this interface to create and start a service. The UUID `6bffd098-a112-3610-9833-46c3f87e345a` is WKSSVC (Workstation Service), used for some remote execution techniques.

On `SRV-EXE-01`, you find a SVCCTL CreateService call followed by a StartService call. The adversary didn't just authenticate—they executed code remotely. This host needs to be your highest-priority forensic target: something ran on it as SYSTEM, and you don't yet know what.

**Path B3 — Authentication Mechanism:**

**Filter:**
```
ntlmssp || kerberos
```

Scoped to the anomalous authentication conversations, examine whether the credential exchange is NTLM (visible as the GSS-API NTLM Security Support Provider blob within SMB Session Setup) or Kerberos (service tickets visible in separate KRB5 exchanges with the domain controller).

**What this reveals:** If the adversary is using NTLM, they're likely using pass the-hash (PTH) with the NT hash harvested from LSASS. If they're using Kerberos, they may have harvested a TGT and are performing pass the ticket. Distinguishing these matters for remediation: PTH requires resetting account passwords; PTT may require invalidating Kerberos tickets (disabling and re-enabling accounts) and potentially rotating the KRBTGT key if a golden ticket is suspected.

In this scenario, the authentication to `SRV-EXE-01` uses NTLM despite Kerberos being available an unusual choice for legitimate users in an AD environment, and a strong indicator of pass-the-hash. Legitimate Windows clients prefer Kerberos when available; tools performing PTH often use NTLM explicitly.

---

### PATH C — Kerberos Analysis

**Filter:**
```
kerberos && (ip.src == 10.10.1.30 || ip.dst == 10.10.1.30)
```

**What surfaces:** All Kerberos exchanges involving WKSTN-IT-003. In a normal workstation environment during business hours, you'd see: a TGT request (AS-REQ/AS-REP) during initial logon, followed by service ticket requests (TGS-REQ/TGS-REP) for each service the user accesses. The TGS-REQ contains the service principal name (SPN) for the requested service this tells you *exactly* what service the user is trying to access before any connection is made.

**Filter for service ticket requests specifically:**
```
kerberos.msg_type == 12
```

`msg_type == 12` is TGS-REQ. Examine `kerberos.req_body.sname` (the SPN being requested) for each request. In this scenario, you'll see a sequence of legitimate TGS requests for known services, followed by requests for SPNs corresponding to the anomalous servers: `cifs/SRV-PAY-01.corp.local`, `cifs/SRV-HR-DB.corp.local`.

A Kerberoasting attempt would appear differently: TGS requests for service accounts (SPNs associated with service accounts rather than computer accounts), where the adversary is requesting tickets to crack offline. In this scenario, the requests are for computer-hosted SMB services, consistent with intended access rather than ticket harvesting.

One anomaly to note: are any TGS-REQ packets missing the corresponding user credential validation (no preceding AS-REQ/AS-REP for the ticket-requesting principal)? That would suggest a ticket was imported from outside rather than legitimately obtained a pass-the-ticket indicator.

> **Instructor Note:** Path C teaches that Kerberos is a rich telemetry source that predates the actual connection attempt. By the time you see an SMB authentication, the Kerberos ticket that authorized it was already requested. Monitoring TGS-REQ patterns gives you foresight you can see the adversary "shopping" for access before they attempt it. This is why Kerberos logging on domain controllers is so valuable in parallel with packet capture.

---

## Playbook 2 Complete — What the Packets Tell You

The lateral movement chain, assembled from all three investigative paths:

1. 10:14: EDR detects LSASS access on WKSTN-IT-003
2. 10:16: LDAP enumeration of domain computers and Domain Admins group
3. 10:19: SMB authentication to SRV-PAY-01 and SRV-HR-DB using NTLM (pass-the-hash indicator)
4. 10:22: File access on both servers—payroll data and employee records
5. 10:31: SMB authentication to SRV-EXE-01, SVCCTL remote service creation and execution

**Containment priority order based on packet evidence:** SRV-EXE-01 (code executed), SRV-PAY-01 (data accessed), SRV-HR-DB (data accessed), WKSTN-IT-003 (origin, preserve evidence).

What remains unknown: what was executed on SRV-EXE-01, whether other hosts were targeted outside the capture window, and the initial access vector for WKSTN-IT-003 itself. These questions require endpoint forensics and extended telemetry analysis.

---
---

# Playbook 3: Application Performance Troubleshooting

## Investigative Frame

**Trigger:** The help desk received 23 tickets in a 90-minute window from users reporting that the CRM application is "extremely slow" and in several cases "timing out." The CRM runs on `SRV-CRM-01` (10.10.5.20), which serves users on the sales subnet (10.10.4.0/24). Infrastructure monitoring shows CPU at 34% and memory at 61% on the server unremarkable. Network monitoring shows no interface errors or drops.

**What you know:** Normal CRM page load for the transaction listing view is under 1.5 seconds. Users are reporting 15–25 seconds. The application uses HTTP/1.1 (internal, not exposed externally), connects to a database server at 10.10.5.25, and passes through a load balancer at 10.10.5.18 that you can ignore for now (it's not load-balancing, just forwarding).

**What you need to determine:** Is the problem in the network (transit latency, packet loss, congestion), in the application server (processing delay, connection exhaustion), or in the database tier? Locate the bottleneck precisely enough that the right team can fix it without guessing.

**The capture:** 30 minutes during peak complaint time from a tap on the segment between the load balancer and SRV-CRM-01.

---

## DECISION POINT 1: Where Is the Delay?

```
┌─────────────────────────────────────────────────────────────────┐
│  Three approaches to locating the bottleneck:                   │
│                                                                 │
│  A → Retransmission analysis                                   │
│      (look for packet loss and retransmission as a cause)      │
│                                                                 │
│  B → TCP latency and server think time                         │
│      (measure where delays actually appear in exchanges)       │
│                                                                 │
│  C → Connection state inspection                               │
│      (look for connection exhaustion or backlog)               │
└─────────────────────────────────────────────────────────────────┘
```

---

### PATH A — Retransmission Analysis

**Filter:**
```
tcp.analysis.retransmission || tcp.analysis.fast_retransmission || \
tcp.analysis.out_of_order
```

**What surfaces:** Wireshark's TCP analysis engine flags retransmissions based on sequence number tracking. If network packet loss is causing the performance problem, you'll see a high volume of retransmissions concentrated on specific conversations or distributed across all conversations (which would suggest a congested path rather than a single flow problem).

**What you should observe in this scenario:** Retransmissions are present but at a normal rate approximately 0.3% of packets, consistent with background noise on a LAN segment. There's no concentration of retransmissions on any particular host or time window. The distribution is even and low.

**What this tells you:** Packet loss is not the cause. The path between clients and the CRM server is healthy. Network congestion explanations are eliminated before you've spent significant time on them. This is a critical negative finding it narrows the problem space substantially. If infrastructure says the network is fine and the packet capture confirms no significant retransmissions, the conversation with the network team is finished and you can redirect focus appropriately.

**Why this is a valuable first check:** Retransmission analysis is fast, decisive, and unambiguous. A high retransmission rate would have immediately pointed to the network layer and ended the application investigation. The absence of retransmissions is just as informative as their presence—it eliminates a category. Starting here prevents the network team and application team from spending days arguing over whose layer is the problem.

**How Path B would have differed:** Path B measures where the delay actually sits in the exchange timeline, which is more specific but takes longer to set up. If retransmissions had been high, you'd use Path B to characterize the impact rather than as a starting point. Here, with no retransmission problem, Path B becomes your logical next step.

**How Path C would have differed:** Connection state inspection would have revealed the problem in a different way you'd see the connection backlog building up (many SYNs without timely SYN-ACKs) and infer that the server is overwhelmed. Path C is particularly suited to connection pool exhaustion scenarios. It doesn't rule out network issues the way Path A does, but it more directly shows the server's symptom.

> **Instructor Note:** Path A teaches the elimination-first principle. In complex systems, characterizing what the problem *isn't* is as important as finding what it is. Beginners often want to go straight to the interesting evidence; experienced investigators often start by ruling out the cheapest explanations.

---

### PATH B — Server Think Time Measurement

**Filter:**
```
http && ip.addr == 10.10.5.20
```

**What surfaces:** All HTTP traffic on the CRM server. Start by examining complete request response pairs. In Wireshark, select an HTTP response packet and look at the `http.time` field in the packet details this is the elapsed time between the request and the response, as calculated by Wireshark from packet timestamps.

For a healthy CRM page load, you'd expect `http.time` values under 1.5 seconds. Apply a filter to surface the slow transactions specifically:

**Filter:**
```
http.time > 5 && ip.src == 10.10.5.20
```

**What surfaces:** All HTTP responses where the server took more than 5 seconds to respond. In this scenario, approximately 68% of responses to the transaction listing endpoint exceed 5 seconds; responses to other endpoints (login, static assets, simple record lookups) respond in under 0.5 seconds. The slowness is endpoint-specific.

This is a significant finding: not all CRM functions are slow specifically the transaction listing view is slow. This means the problem isn't the server being overwhelmed across the board, but something specific about how that view is processed.

**Now look for where the delay occurs within the TCP conversation:**

For one of the slow responses, examine the packet sequence:
1. Client sends the HTTP GET request → arrive at server → server sends TCP ACK (quickly, confirming receipt)
2. Gap — the server has received the request but hasn't started sending the response
3. Server sends the first byte of the HTTP response

The length of the gap between step 1 and step 3 is the server think time pure application processing, no network involved. In this scenario, the gap is consistently 12–18 seconds for the transaction listing endpoint.

**Pivot to the database tier:**

Now filter for traffic between SRV-CRM-01 and the database at 10.10.5.25:

```
ip.addr == 10.10.5.20 && ip.addr == 10.10.5.25
```

Look at the timing of database queries relative to the CRM server's think time. In the packet sequence: the CRM server receives an HTTP request, then immediately opens a connection to the database server (or reuses an existing pooled connection) and sends a query. The database server's response time for that query is visible as the delay between the CRM server's SQL query packets and the database's response packets.

In this scenario, the database response for transaction listing queries takes 11–16 seconds. The CRM server's think time is almost entirely attributable to waiting for the database. The application server is not the bottleneck it's waiting on the database.

> **Instructor Note:** Path B teaches analysts to look for delay at the boundary between components. A complex system that's "slow" has multiple components in a call chain; the delay lives at one boundary. Following the request through that chain HTTP client to app server, app server to database and timing each step locates the boundary where latency accumulates. This is a transferable skill for any tiered application architecture, and it produces actionable, specific findings rather than vague performance complaints.

---

### PATH C — Connection State Inspection

**Filter:**
```
tcp.flags.syn == 1 && ip.dst == 10.10.5.20
```

**What surfaces:** All incoming TCP connection attempts to the CRM server. In a healthy environment during steady load, these should be followed promptly by SYN-ACK responses, with the gap representing normal network RTT. Measure the time between each SYN and its corresponding SYN-ACK:

**Filter for slow SYN-ACK responses:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.src == 10.10.5.20
```

Compare timestamps between SYN and SYN-ACK pairs. If the server is responding to SYNs within 1–2 milliseconds consistently, the TCP stack is healthy and the server isn't in a connection backlog state. If SYN-ACKs are delayed by seconds, the server's accept queue is full—a symptom of connection exhaustion where new connections are queuing because existing ones aren't being processed fast enough.

**In this scenario:** SYN-ACK responses come back within 2–4ms consistently. The connection establishment mechanism is healthy. This tells you the server's TCP stack is not overwhelmed it's accepting connections promptly. The slowness is not at the connection layer but deeper in the application processing stack.

**Filter to check for connection pool exhaustion:**
```
tcp.flags.reset == 1 && ip.src == 10.10.5.20
```

If the application is exhausting its database connection pool and refusing new client connections, you'd see RST packets from the CRM server to clients. In this scenario, RSTs are minimal fewer than 0.1% of connections. The server is not actively refusing connections.

**What Path C rules out:** Connection pool exhaustion and TCP backlog. These are eliminated as explanations. What Path C doesn't tell you (without additional work) is *why* existing connections are slow that requires the response time analysis in Path B.

---

### DECISION POINT 2 (Combined Findings): Database or Application?

You've determined: no significant retransmissions (network is clear), server think time is 12–18 seconds on a specific endpoint, database response time accounts for most of that delay, connection state is healthy.

```
┌─────────────────────────────────────────────────────────────────┐
│  The database query is slow. What's the most likely cause,     │
│  and what can you determine from the pcap?                     │
│                                                                 │
│  C1 → Analyze database query pattern (is the same slow        │
│        query being sent repeatedly?)                           │
│                                                                 │
│  C2 → Examine database connection patterns (connection         │
│        reuse vs. new connections per request?)                 │
│                                                                 │
│  C3 → Determine whether the problem correlates with           │
│        concurrent load (does it get worse under higher        │
│        simultaneous request volume?)                           │
└─────────────────────────────────────────────────────────────────┘
```

**Path C1 — Query Pattern Analysis:**

For this you'd need MySQL or MSSQL protocol dissection. If the database traffic is unencrypted (common on internal database tiers), Wireshark dissects MySQL wire protocol natively. Filter `mysql && ip.addr == 10.10.5.25` and examine `mysql.query` fields in the request packets.

In this scenario, the slow query appears to be a `SELECT` on the transactions table with multiple JOIN clauses and no obvious LIMIT a classic N+1 query pattern or a missing index scenario. The exact query string is visible in the MySQL request packet. Present this to the application team and database administrator: here is the specific query that's taking 12 seconds.

**Path C2 — Connection Reuse Analysis:**

Filter for the TCP conversations between SRV-CRM-01 and SRV-DB-01. Are they reusing a small number of persistent connections (connection pooling working correctly) or opening a new connection per HTTP request (connection pooling broken or not implemented)?

In Conversations view, look at the TCP sessions between these two IPs. A healthy connection pool shows 10–20 long-lived TCP connections with high packet counts per connection. A broken pool shows many short lived TCP connections—many distinct port pairs, each with low packet counts representing single transactions.

If connection pooling is broken, every CRM page request is paying the TCP + application layer connection establishment cost to the database amplifying any latency at the database tier.

**Path C3 — Concurrency Correlation:**

Use `Statistics → IO Graphs` to plot active TCP connections to SRV-CRM-01 over time. Overlay this with response times from Path B. Do response times increase proportionally with connection count, or is the slowness consistent regardless of load?

If slowness is proportional to load, the problem is a shared resource (lock contention, insufficient connection pool size, CPU-bound database operations). If slowness is consistent even at low load (one request at a time, still 12 seconds), the problem is in the query itself likely a missing index or a poorly written query that would be slow regardless of concurrent pressure.

In this scenario: the slowness is consistent even during low concurrency periods. A single isolated request to the transaction endpoint still takes 12 seconds. This eliminates contention and points to the query itself. The DBA needs to examine the execution plan for that query.

---

## Playbook 3 Complete — Deliverable to Each Team

**To the network team:** No significant retransmissions (0.3%), connection establishment latency 2–4ms, no interface errors. Network is not contributing to the observed slowness. Finding closed.

**To the application team:** HTTP response time for the transaction listing endpoint is 12–18 seconds. Server think time accounts for 11–16 seconds of that delay. The application server is waiting on the database. Server CPU and connection pool are not exhausted. The application server layer is not the bottleneck.

**To the database team:** Specific SQL query [text visible in MySQL packets] is executing in 11–16 seconds. The slowness is consistent at low concurrency, which indicates a query structure or indexing problem rather than contention. Recommend examining the execution plan for the identified query.

**What the packets cannot tell you:** Why the query is slow (missing index, table scan, poor join order). That determination requires database layer analysis execution plans, index scans, query optimizer output. The packet capture locates the problem precisely enough that the database team knows exactly what to investigate.

---
---

# Principles

Reading across all three playbooks, several investigative principles recur regardless of scenario type.

**Context determines which filter is the right first filter.** There's no universal starting point. In exfiltration, the proxy architecture made external IP filtering highly efficient. In lateral movement, the broad legitimate profile of the compromised host made discovery first analysis more valuable than connection-first analysis. In performance troubleshooting, retransmission analysis was the fastest way to clear the network layer. The right technique is contextual, not universal.

**Elimination is as valuable as identification.** Path A in the performance playbook finding that retransmissions were not elevated was as important as any positive finding. Conclusively ruling out a category of explanations is investigation progress. Analysts who only feel like they're making progress when they find something suspicious will spend unnecessary time re-examining eliminated hypotheses.

**Packets locate problems; they don't always explain them.** In all three playbooks, the packet analysis identified *where* the problem was occurring the anomalous destination, the lateral movement path, the database query delay but handed off to other disciplines for explanation and remediation. Knowing the boundaries of what packet analysis can answer is as important as knowing what it can reveal.

**Negative space matters.** The absence of DNS precedent for an exfiltration destination, the use of NTLM where Kerberos was available, the absence of RST packets during a performance incident—in each case, what *wasn't* there was as informative as what was. Develop the habit of noting absence, not just presence.
