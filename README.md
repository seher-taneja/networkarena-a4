# NetworkArena — Assignment 4 kit: Take It Live

Your team runs one AS in each of four worlds. You write one program,
`switch.wasm`: it runs on every switch of your AS (exit, queueing,
failover), and it holds your routing policy (which route you use to each
destination, and which you announce to each neighbour). Agreements and
bids are made on the website. Until you sign agreements, every AS reaches
the others only through the Tier-1.

The assignment is in the handout (updated Sat Nov 7); its last section is
the A4 rule book. The hardware handout (hardware, auctions, Auction 1)
adds to the rule book. Give the rule book, the hardware handout and
rules.json to your AI agent. `docs/a4-api-guide.md` is your
API.

## Layout

```
src/  switch_program_types/  switch_program_sdk/   the simulator and the SDK
examples/a4_starter/         the starter switch program: start here (router.rs has the helpers,
                             policy.rs the usual routing policy)
examples/a4_tier1/           the Tier-1's program: part of the world, not yours
examples/settlements/        settlement templates: transit, peering, paid_peering, backup
examples/hello_switch/  examples/learning_switch/   the A1 examples
worlds/practice/             the practice world (practice.toml, a small ring) and full.toml (the
                             full ring you play on); failures/landslide.toml fails two crossings
rules.json                   every number in the A4 rule book (may change until the game opens, Mon Nov 9, 18:00)
viewer/                      browser replay of a run
docs/                        the A4 API guide and the simulator reference
```

## Setup

```sh
rustup target add wasm32-unknown-unknown
cargo build --release
(cd examples/a4_starter && cargo build --release --target wasm32-unknown-unknown)
(cd examples/a4_tier1 && cargo build --release --target wasm32-unknown-unknown)
```

The practice world runs the starter in every AS and the Tier-1's program
in the Tier-1, so build both before the first run.

## Run the practice world

Everyone on the starter:

```sh
./target/release/competitive_net_sim run-a4 worlds/practice/practice.toml
```

Your program in AS 1, the others on the starter:

```sh
./target/release/competitive_net_sim run-a4 worlds/practice/practice.toml \
  --program YOUR_SWITCH.wasm --as 1
```

Each AS gets one line: utility, value (homes and companies), settlements in
and out, the Tier-1 fee, and how much home traffic arrived on time. Add
`--json statement.json` for every AS's full statement.

The full ring (8 exchange points, 32 ASes, everyone on the starter) takes
about five seconds; use `worlds/practice/full.toml` in any command here.

With a landslide: the crossings of AS 1 and AS 2 fail from 3 s to 7 s.

```sh
./target/release/competitive_net_sim run-a4 worlds/practice/practice.toml \
  --program YOUR.wasm --as 1 --failures worlds/practice/failures/landslide.toml
```

## Write your program

Copy `examples/a4_starter/` and edit `src/lib.rs`. It is short: it sends
each destination's traffic along the route your policy chose, through the
nearest exit. Start with three things: which hub traffic leaves from, how
each port queues, and what happens when your crossing fails.

Your routing policy is `src/policy.rs`, the usual rule: `rank` picks the
route your AS uses to each destination, `announce` decides which
neighbours hear about it. Delete the `policy_program!` line and you get
the usual rule anyway. `docs/a4-api-guide.md` says how for both.

```sh
cd examples/a4_starter
cargo build --release --target wasm32-unknown-unknown
# -> target/wasm32-unknown-unknown/release/a4_starter.wasm
```

Each crate's wasm is a file you submit.

## Watch a run

Add `--log run.simlog` to any run, then serve the viewer over HTTP (opening
the file directly will not work: it loads wasm as a module):

```sh
python3 -m http.server -d viewer/web 8080
```

Open <http://localhost:8080> and drag `run.simlog` onto the page. A full
run's replay is large; `--until-ms 3000` keeps it short.

## Reference

| File | What it covers |
|------|----------------|
| `docs/a4-api-guide.md` | A4: what a switch is told, the three decisions, settlement programs, the practice world, hardware you bought. |
| `docs/switch-programs.md` | The SDK, the TinyVM text format, the raw wasm ABI. |
| `docs/LIMITS.md` | Fuel, output size, buffers, queues. |
| `docs/tinyvm.md` | The data-plane instruction set. |
| `docs/sim_log.md` | The `.simlog` format and the viewer. |
