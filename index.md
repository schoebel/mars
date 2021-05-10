# MARS = Multiversion Asynchronous Replicated Storage

![MARS Logo](docu/images/earth-mars-transfer.jpg)

`git clone git@github.com:schoebel/mars.git`

or [https://github.com/schoebel/mars](https://github.com/schoebel/mars)

GPLed software AS IS, sponsored by 1&1 Internet SE ([www.1und1.de](https://www.1und1.de)). Contact: tst@1und1.de

## What is MARS?

MARS can be used to replicate Linux-based storage devices, and even whole datacenters, over arbitrary distances (**geo-redundancy**).

Another use case is **cost-efficient virtual pools of sharded storage**.

At 1&1 Internet SE, it runs at more than 2000 servers and about 2x8 petabytes of customer data.

Main features:
* Anytime Consistency
* Arbitrary Distances
* Tolerates Flaky Networks
* Allows _background_ migration of block devices (optionally combined with traffic shaping)

MARS is almost a drop-in replacement for DRBD (block-level storage replication). It runs as a Linux kernel module.

In contrast to plain DRBD, it works _asynchronously_ and over arbitrary distances. Some of our internal 1&1 testing runs between datacenters in the US and Europe. MARS uses very different technology under the hood, similar to transaction logging of database systems.

Reliability: application and replication are completely decoupled.

Networking problems (e.g. packet loss, bottlenecks) have no impact onto your application at the primary side.

Anytime Consistency: on a secondary node, its version of the underlying disk device is always consistent in itself, but may be outdated (represent a former state from the primary side). Thanks to incremental replication of the transaction logfiles, usually the lag-behind will be only a few seconds, or parts of a second.

Synchronous or near-synchronous operating modes are planned for the future, but are expected to work _reliably_ only over short 
distances (less than 50km), due to fundamental properties of distributed systems.

## Documentation / Manual

See [https://github.com/schoebel/mars/blob/master/docu/mars-user-manual.pdf](https://github.com/schoebel/mars/blob/master/docu/mars-user-manual.pdf)

Intro: the use cases MARS vs DRBD can be found in chapter 1.

**COST SAVINGS** using MARS is described at https://github.com/schoebel/mars/blob/master/docu/MARS_GUUG2017_en.pdf

## Concepts

For a short intro, see my GUUG2016 presentation https://github.com/schoebel/mars/blob/master/docu/MARS_GUUG2016.pdf .

The fundamental construction principle of the planned future MARS Full is called Instance Oriented Programming (IOP) and is described in the following paper: http://athomux.net/papers/paper_inst2.pdf

## History

As you can see in the git log, it evolved from a very experimental concept study, starting in the Summer of 2010.
At that time, I was working on it in my spare time.

Around Christmas 2010, my boss and shortly thereafter the CTO became aware of MARS, and I started working on it more or less "officially".

In Summer 2011, an "official" internal 1&1 project started, which aimed to deliver a proof of concept.

In February 2012, a pilot system was rolled out to an internal statistics server, which collects statistics data from thousands of other servers, and thus produces a very heavy random-access write load, formerly replicated with DRBD (which led to performance problems due to massive randomness). After switching to MARS, the performance was provably better.

In Summer 2012, the next "official" internal 1&1 project started. Its goal was to reach enterprise grade, and therefore to rollout MARS onto ~15 productive servers, starting with less critical systems like ones for test webspaces etc.

In December 2012 (shortly before Christmas), I got the official permission from our CTO Henning Kettler to publish MARS under GPL on github. Many thanks to him!

Before that point, I was probably bound to my working contract which keeps internal software as secret by default (when there is no explicit permission).

Now there is a chance to build up an opensource community for MARS, partially outside of 1&1.

I am trying to respect the guidelines from Linus, but getting MARS upstream into the Linux kernel will need much more work.

In November 2013, internal 1&1 projects started for mass rollout to several thousands of servers at Shared Hosting Linux.

Some other teams, in particular ePages and Mail&Media teams, were starting later but were the first to use MARS at real production in Spring 2014 at about 10 clusters each, with great success. Some of these cluster were even starting with k=4 replicas from scratch, while others were using it as a substitute for pairwise DRBD. I did not have much work with those teams: they just rolled it out, and it worked for them. I got only one bug report from them which I had to fix.

Unfortunately, another team was different. Their rollout process to several thousands of servers took extremely long. After more than a year, only about 50 clusters were migrated to MARS. Eventually, I managed to get MARS fully onto the street in April 2015 by developping a fully automatic rollout script and rolling it out myself during two nights, personally, and by personally taking full responsibility for rollout (and there was no incident). Otherwise, it likely would have taken a few years longer, according to some sysadmins.

Since then MARS is running on several thousands of servers, and on several petabytes of customer data, and it has collected serveral millions of operation hours. It is considered more stable than the hardware now.

## Future Plans / Roadmap

At the moment, cost savings are very important for 1&1. In 2017, MARS will be improved for scalability and load balancing according to the GUUG2017 slides.

Sketch: the traditional pairwise clusters (originally from DRBD pairs) will be merged into one "big cluster" for EU and US each (with respect to _metadata_ updates only, while the IO data paths remain at the sharding principle), such that any resource can be migrated via MARS fast fullsync to any other server. Then background migration of VMs / LXC containers is easily possible for optimizing density and load balancing.

Kernel upstream development is planned to resume later.
