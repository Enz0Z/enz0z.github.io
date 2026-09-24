---
layout: post
title: "Fighting a Minecraft DDoS with 20 Firewall Rules"
date: 2025-03-21
tags: [minecraft, ddos, ovh, python, networking]
---

A few years ago I ran a small Minecraft server on OVH. It was a hobby
project: a handful of regular players, nothing fancy. Then one day someone
decided it would be fun to knock it offline.

This is the story of how I kept it alive with a very limited tool: a
firewall that only lets you write **20 rules**. It's not a bulletproof
solution, and I'll get to its limits at the end, but it was a fun problem
and it worked better than I expected.

## It wasn't the attack I expected

When people hear "DDoS" they usually picture a flood of spoofed packets
coming from millions of random, fake addresses. That's the scary kind,
because there's nobody real to block.

That wasn't what was happening to me. When I looked at the incoming traffic,
the source addresses were *real*, and they clustered. The attacker was
renting machines from a few hosting providers and throwing traffic at my
server from their address ranges. Lots of packets, but from a surprisingly
small number of networks.

That changed everything. If the sources are real and concentrated, you can
block them.

## First idea: just block them on the server

The obvious move was to drop those ranges with `iptables` on the machine
itself. It helps with CPU, but it doesn't solve the actual problem: by the
time a packet reaches your firewall, it has already used up your bandwidth.
If the pipe is full, it doesn't matter that you're politely dropping
everything at the end of it.

The blocking had to happen *before* the traffic reached my server.

## OVH's Edge Network Firewall, and its catch

OVH offers exactly that: the **Edge Network Firewall**, which filters
traffic at the edge of their network, upstream of your server. Blocked
packets never touch your link. Even better, it can be managed through their
API.

The catch: **you only get 20 rules per IP.**

Twenty rules against an attacker using entire provider ranges. Blocking
individual IPs one by one was never going to fit. So the real problem became:
*how do I describe "the bad traffic" in 20 lines or less?*

## Step 1: Count who is actually talking to me

Before blocking anything I needed data: how many packets per second each
source was sending. I didn't want to depend on external tools, so I opened a
raw socket and parsed IPv4 headers myself:

```python
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
...
pkt = s.recv(64)
if len(pkt) >= 34 and pkt[30:34] == me:
    c[pkt[26:30]] += 1
```

A bit of byte arithmetic: the Ethernet header is 14 bytes, and inside the IP
header the source address sits at offset 12 and the destination at 16. So
bytes `26:30` are the source and `30:34` the destination. I only read the
first 64 bytes of each packet, since that's all I need.

One honest caveat: under a real flood, Python *will* drop packets. It simply
can't keep up. But I realized I didn't need exact numbers. What matters is
the **proportions**. If one network is sending 50 times more than everyone
else, that stays true even if I only see half the packets.

## Step 2: What counts as "too much"?

My first instinct was a fixed threshold: more than X packets per second and
you're out. But a fixed number is fragile. A busy evening with lots of
players looks very different from a quiet morning.

So I added a second condition relative to the **median** traffic. A normal
player sends a fairly predictable amount of traffic, so the median is a good
picture of "normal". An attacker sticks out as a massive outlier:

```python
med = statistics.median(pps.values())
thr = {**THRESH, 32: max(THRESH[32], K_MEDIAN * med)}
```

For a single IP to be flagged, it has to exceed an absolute minimum *and* be
more than 20 times the median. The median is robust: even if a few attackers
are screaming, they don't drag it up the way an average would.

## Step 3: Think in networks, not addresses

Here's where the pattern of the attack became useful. The attacker wasn't
using one IP, they were using many IPs *within the same provider's range*.
Individually, each one might look harmless. Together, they were the problem.

So instead of only looking at `/32` (single addresses), I aggregated traffic
at `/24`, `/16` and `/8`, each with its own threshold:

```python
THRESH = {32: 300, 24: 1500, 16: 6000, 8: 25000}
...
for ip, v in pps.items():
    for lvl in THRESH:
        agg[lvl][ipaddress.ip_network(f"{ip}/{lvl}", strict=False)] += v
```

A `/24` full of machines each sending a "reasonable" amount now adds up to a
very unreasonable total, and gets caught as a block. This was the key idea:
one rule can cover 256 addresses, or 65,536, if that's what it takes.

Of course, I also added a whitelist, so the script would never ban my own IP
or any network I explicitly trust.

## Step 4: Squeezing everything into 20 slots

Detection could now return more networks than I had rules for. I needed a
way to compress them.

The first pass is free: Python's `ipaddress.collapse_addresses` merges
adjacent and overlapping networks. But if that's still too many, I have to
start making trade-offs and block a bigger range than strictly necessary.

The approach is greedy: look at every possible "parent" network, pick the
one that absorbs the most current entries, merge, and repeat until it fits:

```python
while len(nets) > BUDGET:
    cands = [n.supernet(new_prefix=l) for n in nets for l in (24, 16, 8) if n.prefixlen > l]
    sup = max(cands, key=lambda s: (sum(o.subnet_of(s) for o in nets), s.prefixlen))
    nets = set(ipaddress.collapse_addresses(nets | {sup}))
```

It's O(n²) per iteration, which sounds bad until you remember that *n* is a
few dozen at most. Not worth optimizing.

I also kept the first 4 rule slots reserved for fixed rules I managed by
hand, so the script only plays with the remaining 16.

## Step 5: Talking to OVH

With a list of networks to block, the last piece was syncing it with the
firewall through the OVH API. Requests are signed with a SHA1 of your
secret, consumer key, method, URL, body and timestamp, nothing exotic.

The sync logic compares what's there with what should be there: delete what
is no longer needed, add what's missing.

```python
for seq, (n, st) in current.items():
    if n is not None and n not in desired and st == "ok":
        self.call("DELETE", f"{RULES}/{seq}")
free = [s for s in range(RESERVED, 20) if s not in current]
```

There was one detail that bit me: deleting a rule isn't instant. A rule being
removed still occupies its slot for a while. So the script only considers a
slot free once it has actually disappeared, and if there's no room yet, the
new ban simply waits for the next cycle.

## Step 6: Bans that expire

Attackers move around, and I didn't want to block a range forever just
because it misbehaved once. Every ban gets a TTL (10 minutes by default), and
it's renewed as long as the network keeps attacking:

```python
for n in offenders(pps):
    bans[n] = now + BAN_TTL
bans = {n: t for n, t in bans.items() if t > now}
```

Two more small things made it more robust. On startup, the script *adopts*
any rules that already exist, so restarting it doesn't wipe active
protection. And if the OVH API fails (which happens surprisingly often
exactly when you're under attack), it just logs the error and tries again on
the next loop.

I also added a `--dry-run` mode, which turned out to be essential: it lets
you watch what the script *would* block before trusting it with the real
firewall.

## Did it work?

Yes, for this kind of attack. The traffic was coming from real ranges, the
script found them, compressed them into a handful of rules, and OVH dropped
them before they ever reached my link. The server stayed playable.

## Where it falls short

I want to be clear that this was a temporary fix for a specific kind of
attack, not a real DDoS solution.

**Spoofed traffic breaks it.** If the source addresses are random and fake,
there's no pattern to aggregate. The script would either block nothing
useful or burn through its 20 rules chasing ghosts.

**Aggressive aggregation has collateral damage.** Blocking a `/16` or a `/8`
to fit the budget can take out legitimate players who happen to share that
range.

**You can lock yourself out.** This is the scary one. If the script ends up
blocking a range that includes the address you use to administer the
server, you lose access to it. At that point the only way back in is through
the OVH control panel, deleting the rule by hand. The whitelist exists for
exactly this reason, and you should fill it in before you ever run this for
real.

Still, with nothing more than a raw socket, some counting and a greedy
algorithm, it turned a very limited tool into something that genuinely
protected the server. Sometimes 20 rules are enough, if you're careful about
how you write them.
