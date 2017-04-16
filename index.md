# MARS = Multiversion Asynchronous Replicated Storage

![MARS Logo](docu/images/earth-mars-transfer.jpg)

`git clone git@github.com:schoebel/mars.git`

or https://github.com/schoebel/mars

GPLed software AS IS, sponsored by 1&1 Internet AG (www.1und1.de). Contact: tst@1und1.de

## What is MARS Light?

MARS can be used to replicate Linux-based storage devices, or even whole datacenters, over arbitrary distances (geo-redundancy).

Main features:
* Anytime Consistency
* Arbitrary Distances
* Tolerates Flaky Networks

MARS Light is almost a drop-in replacement for DRBD (block-level storage replication). It runs as a Linux kernel module.

In contrast to plain DRBD, it works _asynchronously_ and over
arbitrary distances. Our internal 1&1 testing runs between datacenters
in the US and Europe. MARS uses very different technology under the
hood, similar to transaction logging of database systems.

Reliability: application and replication are completely decoupled.
Networking problems (e.g. packet loss, bottlenecks) have no
impact onto your application at the primary side.

Anytime Consistency: on a secondary node, its version of the underlying
disk device is always consistent in itself, but may be outdated
(represent a former state from the primary side). Thanks to
incremental replication of the transaction logfiles, usually the
lag-behind will be only a few seconds, or parts of a second.

Synchronous or near-synchronous operating modes are planned for
the future, but are expected to work _reliably_ only over short 
distances (less than 50km), due to fundamental properties
of distributed systems.

WARNING! Current stage is BETA. It has been already tested with productive data, but there is no guarantee (as with any GPL software).

## Documentation / Manual

See https://github.com/schoebel/mars/blob/master/docu/mars-manual.pdf

Intro: the use cases MARS vs DRBD can be found in chapter 1.

## Concepts

For a very short intro, see my LCA2013 presentation https://github.com/schoebel/mars/blob/master/docu/MARS_LCA2013.pdf .

There is also an internal 2-years old concept paper which is so much outdated,
that I don't want to publish it. 

The fundamental construction principle of the planned MARS Full
is called Instance Oriented Programming (IOP) and is described in
the following paper:

http://athomux.net/papers/paper_inst2.pdf

## History

As you can see in the git log, it evolved from a very experimental
concept study, starting in the Summer of 2010.
At that time, I was working on it in my spare time.

In Summer 2011, an "official" internal 1&1 project started, which aimed
to deliver a proof of concept.

In February 2012, a pilot system was rolled out to an internal statistics
server, which collects statistics data from thousands of other servers,
and thus produces a very heavy random-access write load, formerly
replicated with DRBD (which led to performance problems due to massive
randomness). After switching to MARS, the performance was provably
better.

After curing some small infancy problems, that server runs until today
without problems. It was upgraded to newer versions of MARS several
times (indicated by some of the git tags). Our sysadmins switched the
primary side a few times, without informing me, so I could
sleep better at night without knowing what they did ;)

In Summer 2012, the next "official" internal 1&1 project started. Its goal
was to reach enterprise grade, and therefore to rollout MARS Light on
~15 productive servers, starting with less critical systems like ones
for test webspaces etc.

In December 2012 (shortly before Christmas), I got the official permission
from our CTO Henning Kettler to publish MARS under GPL on github. Many thanks to him!

Before that point, I was bound to my working contract which kept internal
software as secret by default (when there was no explicit permission).

Now there is a chance to build up an opensource
community for MARS, partially outside of 1&1.

I will also try to respect the guidelines from Linus, but probably this
will need more work. I am already planning to invest some time into
community revision of the sourcecode, but there is not yet any schedule.

In May 2013, I got help by my new collegue Frank Liepold. He is working
on a fully automatic test suite which automates regression tests
(goal: rolling releases). That test suite is based on the internal
test suite of blkreplay and can be found in the test_suite/ subdirectory.

More than 15 pilot clusters serving real customers are running for several months since Summer 2013. Some of there are known "performance pigs". There were no issues worth mentioning (besides collecting operational experiences, HOWTO do things the right way, finding the best monitoring strategies, etc).

In November 2013, internal 1&1 projects started for mass rollout to several thousands of servers.

Although the software continues to be labelled "beta" for the next future, it has reached enterprise grade due to our internal rating process.

## Future Plans / Roadmap

Smaller Reworks: in Winter 2013/2014, some smaller changes to the symlink tree are planned, in order to make it more readable for humans and to prepare for future enhancements. They will only change the syntax, not the semantics. There will be an upgrade plan, i.e. the old symlink tree remains usable; only newly created clusters will use the new structure.

In parallel, the software will be internally divided into three parts (mostly syntactical renames automated by a script):

1. Generic brick framework
2. AIO personality with XIO bricks
3. MARS Light application

I hope this will make MARS more attractive for the mainline Linux kernel community. When everything runs fine, the upstream code revision could start in Spring 2014.

MARS FULL is planned in the following steps:

1. MARS FULL infrastructure, IOP replacement for the ad-hoc Light instantiation logic, functionally equivalent (regression testing with Frank's test suite).
2. Remote device. `/dev/mars/mydata` can appear anywhere in a cluster, independently from primary switching. Estimated release date: end of 2014.
3. Virtual point-in-time restore. Creates a read-only snapshot on-the-fly, for any unplanned time in the past (provided that transaction logs have not yet been deleted), with second resolution. Estimated release date: end of 2015.

Further MARS FULL features are possible, but there is no schedule yet.
