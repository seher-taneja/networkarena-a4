# A4 API guide

This guide is the programming interface for A4. You submit a switch
program and, if you like, settlement programs; nothing else is code: agreements and bids are
made on the website. Your AI may write any of them.

| Program | What it decides | Section |
|---|---|---|
| `switch.wasm` | your network (exit, queueing, failover) and your routing policy (which route you use, which you announce) | 1, 2, 3 |
| settlement programs | what an agreement pays (templates need no code) | 4 |

The rules (money, agreements, rounds) are in the A4 rule book (the handout's last section) and the
hardware handout, which adds to it; the numbers are in `rules.json`. Hardware you bought is
Section 6. Until you sign agreements, every AS reaches the
others only through the Tier-1.

## 1. Your switch program

One program, as in A1 to A3, runs on every switch of your AS, in every
world. Start from `examples/a4_starter/`. Implement `init_with` (not
`init`): in an A4 world, `input.a4` is always present.

```rust
impl SwitchProgram for MyProgram {
    fn init_with(input: InitInput) -> (Self, ProgramSetup);
    fn on_punt(&mut self, ev: PuntEvent) -> Vec<Action>;
    fn on_timer(&mut self, ev: TimerEvent) -> Vec<Action>;
}
```

Every switch gets one timer at time 0; schedule more with
`actions::schedule_timer(ns)`.

### What a switch is told: `input.a4` (`wire::A4InfoW`)

Every switch of your AS gets the same picture of the AS (only
`queue_bytes` is the switch's own):

| Field | What it is |
|---|---|
| `as_id` | your AS number in this world |
| `switches` | every switch of your AS |
| `internal` | every link between two of your switches: `(a, a_port, b, b_port)` |
| `borders` | every port of your switches that leaves the AS: `(switch, port, peer_as, rel)` |
| `own` | your own address blocks (homes and companies): `(addr, len, switch, port, class)`; deliver these inside the AS |
| `routes` | the routes your policy chose: for each destination, the neighbour you use, on every link to it |
| `queue_bytes` | this switch's buffer: each port's queue, in bytes (the switch's pool is this times its ports) |

Each route (`wire::A4RouteW`) is `addr/len`, reached through `port` of
`switch`, with:

- `rel`: who the neighbour is to you. `A4_CUSTOMER`, `A4_PEER`,
  `A4_PROVIDER`, `A4_BACKUP`, or `A4_TIER1`.
- `as_path`: the ASes the traffic crosses, the neighbour first.
- `med`: the neighbour's hint about its own entry points. Lower means the
  block is nearer that link. It is 0 for routes the neighbour heard from
  others.

The Tier-1 always offers `0.0.0.0/0`, on your Tier-1 link at each hub.

Your switch program does not choose the neighbour: your policy
(Section 2) did, before the round. It chooses the exit: which of the links
to that neighbour, or which Tier-1 link, each switch uses. A destination
your policy sends to the Tier-1 has no specific route here, so it takes
`0.0.0.0/0`.

`input.port_capacity_bps` gives each port's capacity, parallel to
`input.local_ports`. Hardware you bought shows up in these fields
(Section 6).

### Traffic classes

A packet's class is in its IP DSCP field: `A4_WEB` 1, `A4_VIDEO` 2,
`A4_CALLS` 3, `A4_TRADING` 4. The targets are in `rules.json`. Over the
Tier-1, Web arrives on time, Video until the links fill, Calls only
sometimes, and Trading never.

### Where the traffic goes

`rules.json` `traffic` has each AS's average rates by class, in real Mb/s:
- what each company's site through your AS sends;
- what your homes send to other sectors;
- what reaches your homes from content behind the Tier-1.

Its notes say where each kind goes. Two consequences:
- Company traffic through your AS goes to all eight home sites in your
  sector, so three quarters of it is delivered into your sector-mates'
  homes. Your q for that company counts all of it, both directions.
- Jane Street's site through your AS trades with its sites through every
  AS outside your sector.

Packets arrive at random around these averages, and every round draws its
own. The practice world files (`[[a4.app]]`) list every source's rate
there.

## 2. Your routing policy (in `switch.wasm`)

Your routing policy is two functions in your switch program. Leave them
out and you get the usual rule. Before a round, the platform works out every AS's routes together. Over
and over, until no AS changes its mind, it asks each AS's policy two
questions:

```rust
// Of these routes to destination AS `input.dest`, which do you use?
fn rank(input: &wire::RankInputW) -> usize;
// Do you tell neighbour `input.to` about the route you use to `input.dest`?
fn announce(input: &wire::AnnounceInputW) -> bool;
// In src/lib.rs, beside switch_program!(...):
switch_program_sdk::policy_program!(policy::rank, policy::announce);
```

- **A route** (`wire::PolicyRouteW`): the `neighbour` it came from, `rel`
  (who that neighbour is to you: `A4_CUSTOMER`, `A4_PEER`, `A4_PROVIDER`,
  `A4_TIER1`, or `A4_OWN` for your own blocks), and `as_path` (the
  neighbour first, the destination last).
- **`rank`** gets `as_id` (you), `dest` and `routes`: every route your
  neighbours announced to you for `dest`, and the Tier-1, always last.
  Return the index of the one you use. Your switches then send that
  destination's traffic to that neighbour.
- **`announce`** gets `as_id`, `dest`, `route` (the one you use), `to` (the
  neighbour) and `to_rel` (who it is to you). Return `true` to announce:
  that neighbour may then send you traffic for `dest`, and you carry it.

What the platform does for you: you are offered only routes over your
signed agreements; a route whose path already contains you is dropped;
routes through the Tier-1 are never passed on; backup routes and what the
Tier-1 hears are handled for you.

**The usual policy** is `examples/a4_starter/src/policy.rs`, and a switch
program without `policy_program!` gets exactly it: rank customer over
peer over provider, with the Tier-1 last, then the shortest AS path;
announce your own and your customers' routes to everyone, and your peers'
and providers' routes only to your customers (Gao-Rexford). Announcing
more is a **leak**: you carry traffic between two other networks, and
nobody pays you for it. Announcing less can leave you with no traffic to
carry, and no money from it.

**Settling.** The platform stops when no AS changes its routes, or after
32 passes. If policies keep changing each other's routes, the round uses
the last pass and every statement says the routes did not settle.

**Failure.** If your policy traps, runs out of fuel (10 million per
call), returns an index out of range or an answer other than true or
false, your AS uses the usual policy for the whole round, and your
statement says why. Keep it fast: it is called many times per round.

**No memory between calls.** Every call runs on a fresh instance of your
program: globals and memory start as they are in the module, so nothing
you store in one call is there in the next, and nothing your running
switches store is there either. Your answer must follow from the input
alone.

It builds with your switch program:

```sh
(cd examples/a4_starter && cargo build --release --target wasm32-unknown-unknown)
```

## 3. Your own network: three decisions

### Exit

For traffic that leaves your AS, choose the hub it leaves from. You can
hand it to the Tier-1 at the nearest hub (what the starter does), or carry
it across your crossing and hand it off at the other hub. The starter's
exit ranking, `fn rank` in `examples/a4_starter/src/lib.rs` (not the
policy's `rank` in `policy.rs`), is where this is decided: change what it
ranks first.

### Queueing

`actions::set_queues(port, discipline, queues)` gives a port its queues:
`Discipline::{Fifo, StrictPriority, Drr}` and `QueueSpec::new(cap)`. The
data plane picks a queue per packet. `router::setup(routes, true)` in the
starter's `router.rs` already sends Calls and Trading to queue 0 and the
rest to queue 1; pair it with a two-queue `StrictPriority` port. Buffers
are in `rules.json`; a switch's own is `input.a4.queue_bytes`. Queue caps
(`QueueSpec::new(cap)`) are in packets of 1000 bytes.

### Failover

When your crossing fails, your two towns can reach each other only through
the Tier-1 (or a neighbour you have an agreement with). Nothing tells your program
that a link failed. Notice it yourself:

1. On every timer, send a small hello packet out of each internal port:
   `actions::inject_packet(port, src, dst, router::PROTO_HELLO, 1, vec![])`.
   `router::setup` punts every hello to the controller, so `on_punt` sees
   the hellos your neighbours send (`ev.ip_proto == router::PROTO_HELLO`,
   on `ev.ingress_port`).
2. A port you have not heard from for a few timers is down.
3. Recompute the table without it (`router::table` takes a set of down
   `(switch, port)` pairs) and replace the installed routes
   (`router::reinstall`).

Keep the timer short compared with the outage, and the hello small: it
uses the link like any packet. Packets your program sends never appear
on a meter or in a settlement, on any border; only customer traffic does
(the Tier-1 fee counts them like any Mb on your Tier-1 links). Each
switch may send at most `switch_program.inject_bytes_per_s` of them a
second (10,000 bytes, plenty for hellos on every port); the excess is
dropped and the replay shows it.

## 4. Settlement programs

Every agreement is a small wasm program that reads our meters after a
round and returns one amount. Templates are in `examples/settlements/`:
`transit`, `peering`, `paid_peering`, `backup`. Each is a crate:

```rust
fn settle(input: &wire::SettleInputW) -> i64 { ... }
switch_program_sdk::settlement_program!(settle);
```

- **Input** (`wire::SettleInputW`): the two ASes `a` and `b` as signed,
  the `terms` (filled-in numbers, by name), the meter epoch and round
  length, the `readings` on the links between the two ASes, and the
  round's `outages` for both ASes.
- **A reading** (`wire::ReadingW`) is one epoch, one direction (`from`,
  `to`), one class: `bytes`, and how they ended: `on_time`, `late`, `lost`;
  `returned` is traffic that crossed to `to` and came straight back to
  `from` (`from`'s own traffic, carried between its towns), and
  `returned_on_time` the part of that on time. Bytes are at the real
  rates.
- **Helpers:** `input.term("price")`, `input.sum(from, to, |epoch| ...)`,
  `wire::per_mb(price, bytes)`.
- **Output:** what `a` pays `b`, in **millionths of a dollar**; negative
  means `b` pays `a`. Terms are in millionths too: a price of $2.10 per
  Mb is `2_100_000`.
- The result is capped at the agreement's signed maximum, either way. A
  program that traps or runs out of fuel pays nothing that round.

Build one like any crate:

```sh
(cd examples/settlements/transit && cargo build --release --target wasm32-unknown-unknown)
```

## 5. Running the practice world

The practice world (`worlds/practice/practice.toml`) is a small ring: four
exchange points, sixteen ASes, a Tier-1, homes and companies. Every AS
runs the starter. It runs at a tenth of the real rates; money is computed
on real Mb. A run takes a few seconds.

`worlds/practice/full.toml` is the full ring you play on: eight exchange
points, 32 ASes, a Tier-1, every AS on the starter, also at a tenth of the
real rates. It has the game's map and traffic pattern, but not the other
teams, their agreements or the failures. A run takes about five seconds.
The commands below work on either file; the website's dry run uses
`practice.toml`.

Put your switch program, with its policy, in one AS with `--as`:

```sh
./target/release/competitive_net_sim run-a4 worlds/practice/practice.toml \
  --program YOUR_SWITCH.wasm --as 1
```

Each AS gets one line: utility, value (homes and companies), settlements
in and out, the Tier-1 fee, and how much home traffic arrived on time.
Add:

- `--json statement.json` for every AS's full statement;
- `--log run.simlog` for the replay (open it in the viewer);
- `--failures worlds/practice/failures/landslide.toml` for a landslide:
  the crossings of AS 1 and AS 2 fail from 3 s to 7 s. Put your program
  in AS 1 or 2 to test failover.

### Trying an agreement locally

Add an `[[a4.agreement]]` to a copy of the practice world and run it. Every
two ASes that share an exchange point are already linked there; a link
carries traffic only once an agreement covers it.

```toml
[[a4.agreement]]
kind = "peer"            # "peer", "transit" (a buys from b) or "backup" (a buys from b)
a = 1
b = 3
program = "../../examples/settlements/peering/target/wasm32-unknown-unknown/release/settle_peering.wasm"
terms = { }              # in dollars, e.g. { price = 0.8 }
max = 1000               # the most either side pays in a round, in dollars
```

The statement then shows what the agreement paid, and your policy's
`rank` sees the routes it created. Paid peering is `kind = "peer"` with the
`paid_peering` program.

## 6. Hardware you bought

Hardware installed in a world is part of that world's file from the next
cutoff, and your switch program sees it at start-up like the rest of your
network. Nothing new to call. Your one program runs in all four worlds,
and each world may have different hardware, so read it from the input;
do not assume it.

| Item | In the world file | What your program sees |
|---|---|---|
| Second cable | your crossing's `capacity_mbps` is larger | the crossing ports' `port_capacity_bps` |
| Link capacity upgrade | that link's `capacity_mbps` is larger | that link's `port_capacity_bps` |
| Faster port | your links at that IXP are larger | those border ports' `port_capacity_bps` |
| Private interconnect | your link to that neighbour at that IXP is larger | that border port's `port_capacity_bps` |
| Link across the ring | a new switch of yours (`[[switch]]`), a link from your hub to it, and links from it to the ASes at the far IXP | the switch in `switches`, the hub link in `internal`, its ports in `borders`, and routes on them in `routes` |
| Buffer upgrade | `queue_capacity_bytes` on that `[[switch]]` | `input.a4.queue_bytes` on that switch |
| Program memory | `memory_bytes` on your `[[a4.as]]` | nothing; your program may grow its memory further |
| Repair crew | your failed links come back sooner in the round's failures | nothing; your hellos hear the link again sooner |

The starter needs no change for any of these: it builds its table from
`internal`, `borders` and `routes`, so a new switch and its routes are
used as soon as an agreement offers them. A link across the ring still
carries nothing until you have an agreement with an AS at the far IXP:
until then no route is offered on it.

### Trying hardware locally

Add the lines to a copy of a practice world in `worlds/practice/` (the
program paths in it are relative to that folder), as for an agreement
(Section 5). Two things to know about the files:

- **Units.** `capacity_mbps` is in simulated Mb/s: the real number times
  the world's `mb_scale` (0.1 in both practice worlds). `latency_us` is in
  microseconds. The real numbers are in `rules.json` (`network`,
  `hardware`).
- **Switch numbers.** AS `a` in sector `s` has hubs `10a+1` (at IXP `s`)
  and `10a+2` (at IXP `s+1`), and access switches `10a+3` and `10a+4`.
  The ASes at IXP `j` are the `10a+1` hubs of sector `j` and the `10a+2`
  hubs of sector `j-1`. Across the ring from IXP `j` is IXP `j+4` on the
  full ring (`full.toml`, 8 IXPs) and `j+2` in `practice.toml` (4 IXPs).
  A link across the ring is switch `10a+5`.

The game's worlds use the same numbering. For example, on the full ring
AS 1 (sector 0) buys a microwave link across the ring from hub 11 (IXP 0)
to IXP 4, where the ASes are 17 to 20 (hubs 171 to 201) and 13 to 16
(hubs 132 to 162), and a buffer upgrade on the new switch:

```toml
[[switch]]
id = 15
as_id = 1
queue_capacity_bytes = 25000     # buffer upgrade: 12500 + hardware.upgrades.buffer_bytes_per_port

[[link]]                         # microwave: 50 real Mb/s x 0.1, 12 ms
a = 11
b = 15
capacity_mbps = 5
latency_us = 12000

[[link]]                         # the far port, to AS 17: 200 x 0.1, 1 ms
a = 15
b = 171
capacity_mbps = 20
latency_us = 1000

# ... the same [[link]] from 15 to 181, 191, 201, 132, 142, 152 and 162
```

Then add an `[[a4.agreement]]` with AS 17 (Section 5): without one the
link carries nothing. On the full ring, with every AS on the starter,
this, with peerings with AS 17 and AS 13, raised AS 1's utility from
about $0 to about $680 a run, and each partner's by about $600.

The other items:

- **Second cable**, **link capacity** and **private interconnect**: raise
  `capacity_mbps` on that `[[link]]` by the item's real number times
  `mb_scale`. AS 1's crossing is the link `11`-`12`; its link to AS 2 at
  IXP 0 is `11`-`21`.
- **Faster port**: the same, on each of your links at that IXP (AS 1 at
  IXP 0: every link from hub 11 to another AS's hub).
- **Program memory**: add `memory_bytes = 268435456` (the base
  `switch_program.memory_bytes` plus `hardware.upgrades.program_memory_bytes`)
  to your `[[a4.as]]` row. Your submitted program must still pass its dry
  run at the base limit.
- **Repair crew**: in a copy of the failure file, bring each of your
  links back earlier: `up_ms = down_ms + hardware.repair_crew.outage_factor
  * (up_ms - down_ms)`. With the landslide, AS 1's crossing then comes back
  at 5 s, not 7 s.
