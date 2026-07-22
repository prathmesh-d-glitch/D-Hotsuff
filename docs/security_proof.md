# D-HotStuff Security Proof Mapping

This document maps each security theorem from the D-HotStuff paper (Theorems 5–13)
to the corresponding Go source code that implements or enforces it, and to the
test cases that verify the property.

## Summary Table

| Theorem | Property | Key Code Location | Test Location |
|---------|----------|-------------------|---------------|
| **5** | Same Configuration Delivery | [config_store.go](file:///d:/GO/d-hotstuff/internal/membership/config_store.go#L79-L99) `Install()` + [deliver.go](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L94-L138) conf_number tagging | [property_test.go](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) `TestSameConfigDelivery` |
| **7** | Total Order | [deliver.go](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L153-L158) `CheckThreeChain` + [safety.go](file:///d:/GO/d-hotstuff/internal/consensus/safety.go#L72-L89) `SafeNode` | [property_test.go](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) `TestTotalOrder` |
| **10** | Agreement | [discovery.go](file:///d:/GO/d-hotstuff/internal/discovery/discovery.go#L89-L141) `SyncIfBehind` + [safety.go](file:///d:/GO/d-hotstuff/internal/consensus/safety.go#L72-L89) | [property_test.go](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) `TestAgreement` |
| **11** | Integrity | [deliver.go](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L57) `delivered` map + [deliver.go](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L98-L101) idempotency guard | [consensus_test.go](file:///d:/GO/d-hotstuff/internal/consensus/consensus_test.go) `TestDeliverOnce` + [property_test.go](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) `TestIntegrity` |
| **12** | Liveness | [viewchange.go](file:///d:/GO/d-hotstuff/internal/consensus/viewchange.go#L94-L122) `OnTimeout` + [committee.go](file:///d:/GO/d-hotstuff/internal/membership/committee.go) `Leader()` | [property_test.go](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) `TestLiveness` |
| **13** | Consistent Delivery | Composite of Theorems 10 + 11 + 12 | [adversary_test.go](file:///d:/GO/d-hotstuff/tests/integration/adversary_test.go) `TestByzantineLeaderEquivocation` |

---

## Theorem 5 — Same Configuration Delivery

> **Statement**: If two honest replicas P_i and P_j both deliver a value v, then
> they do so in the same configuration: c_i = c_j.

### Implementation

The guarantee is enforced by two cooperating mechanisms:

1. **Configuration-tagged blocks**: Every `Block` carries a `conf_number` field
   ([dhotstuff.proto L111](file:///d:/GO/d-hotstuff/proto/dhotstuff.proto#L111)).
   The leader stamps each block with `mc.Number` from its current committee
   ([dhotstuff.go](file:///d:/GO/d-hotstuff/internal/consensus/dhotstuff.go) `propose()`).

2. **Monotonic config installation**: [config_store.go Install()](file:///d:/GO/d-hotstuff/internal/membership/config_store.go#L79-L99)
   enforces `next.Number == len(configs)` — strictly sequential.  Because
   `Deliver()` looks up the committee via `configs.AtNumber(block.ConfNumber)`,
   all replicas that deliver the same block necessarily use the same
   configuration epoch.

3. **Deliver conf-number matching**: [deliver.go Deliver()](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L94-L138)
   retrieves the committee from the config store using the block's `conf_number`
   and only applies membership changes to produce `Mc+1`.  This ensures the
   configuration tag on the block is the source of truth.

### Tests

- [TestSameConfigDelivery](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) — for n∈{4,7,10} with
  3 churn events, verifies that every pair of deliveries with the same `Cmd`
  has the same `ConfigNumber`.

---

## Theorem 7 — Total Order

> **Statement**: If honest replica P_i delivers v before v', then no honest replica
> P_j delivers v' before v.

### Implementation

Total order is ensured by two mechanisms:

1. **Three-Chain commit rule**: [CheckThreeChain](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L153-L158)
   requires four consecutive parent-link blocks (`bStar→bDouble→bPrime→b`) before
   committing block `b`.  Since the parent chain is a linear sequence (hash-linked),
   all replicas that observe the same three-chain commit the same block at the same
   height.

2. **SafeNode safety clause**: [SafeNode](file:///d:/GO/d-hotstuff/internal/consensus/safety.go#L72-L89)
   prevents equivocation.  The safety rule (`bc.Extends(node.ParentHash, lockedQC.BlockHash)`)
   ensures a replica only votes for blocks that extend its locked chain, preventing
   forks at the same height.

3. **Batch ordering**: [Deliver()](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L104-L134)
   processes regular requests before membership requests within each block (§4.5),
   ensuring deterministic intra-block ordering.

### Tests

- [TestTotalOrder](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) — for every pair of honest
  replicas, verifies that if replica A delivers cmd₁ before cmd₂, replica B also
  delivers cmd₁ before cmd₂.
- [TestSafeNodeSafetyRule](file:///d:/GO/d-hotstuff/internal/consensus/consensus_test.go) — verifies that
  SafeNode blocks equivocation when QC view equals locked view.

---

## Theorem 10 — Agreement

> **Statement**: If an honest replica P_i in configuration c delivers v at height h,
> then all honest replicas in configuration c deliver v at height h.

### Implementation

Agreement relies on three components:

1. **Quorum intersection**: [QuorumSize()](file:///d:/GO/d-hotstuff/internal/membership/committee.go)
   computes `Qc = ceil((nc + fc + 1) / 2)` which guarantees that any two quorums
   share at least one honest replica.  This means two conflicting QCs cannot both
   be valid.

2. **Configuration synchronization** (Lemma 9: c-honest replicas): 
   [SyncIfBehind](file:///d:/GO/d-hotstuff/internal/discovery/discovery.go#L89-L141) ensures
   that replicas behind the latest configuration catch up before participating.
   The update protocol contacts `nc″ − fc″` replicas and validates the best block
   via `safeNode`, preventing Byzantine replicas from feeding a stale or forked state.

3. **ValidateQC**: [ValidateQC](file:///d:/GO/d-hotstuff/internal/membership/quorum.go) verifies
   that a QC contains `Qc` distinct valid signatures from known committee members,
   ensuring that a QC can only form for one block per view.

### Tests

- [TestAgreement](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) — for each height h, all
  honest replicas deliver the same command.
- [TestByzantineLeaderEquivocation](file:///d:/GO/d-hotstuff/tests/integration/adversary_test.go) — verifies
  that equivocation by a Byzantine leader cannot produce two valid QCs (neither
  subset reaches quorum).

---

## Theorem 11 — Integrity

> **Statement**: For each correct replica P_i and each value v: P_i delivers v at
> most once.

### Implementation

Exactly-once delivery is enforced by [Deliverer](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L47-L59):

```go
type Deliverer struct {
    // ...
    delivered map[string]bool // blockHash → already delivered
    mu        sync.Mutex
}
```

The idempotency guard at [deliver.go L98-L101](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L98-L101):

```go
key := string(hashBlock(block))
if d.delivered[key] {
    return nil // already delivered — idempotent no-op
}
```

After successful delivery, the block hash is marked at the end:

```go
d.delivered[key] = true
```

The `sync.Mutex` ensures thread safety for concurrent delivery attempts.

### Tests

- [TestDeliverOnce](file:///d:/GO/d-hotstuff/internal/consensus/consensus_test.go) — calls
  `Deliver(block)` twice; `countingExecutor` verifies `Execute` is called exactly once.
- [TestIntegrity](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) — for each replica, checks
  that no command appears more than once in its delivery sequence.

---

## Theorem 12 — Liveness

> **Statement**: After GST, if a value v is submitted by a correct client, then v
> is eventually delivered by all correct replicas.

### Implementation

Liveness depends on **Lemma 1** (honest leader eventually entered), which is
implemented by the view-change sub-protocol:

1. **OnTimeout** ([viewchange.go](file:///d:/GO/d-hotstuff/internal/consensus/viewchange.go#L94-L122)):
   When the view timer expires, the replica increments `curView` and sends a
   `NewViewMsg` to the next leader.  This ensures that failed views eventually
   rotate to an honest leader.

2. **Leader rotation** ([committee.go Leader()](file:///d:/GO/d-hotstuff/internal/membership/committee.go)):
   `Replicas[view % len(Replicas)]` implements round-robin rotation.  After at most
   `fc` consecutive Byzantine leaders, an honest leader is reached.

3. **OnNewViewMessages** ([viewchange.go](file:///d:/GO/d-hotstuff/internal/consensus/viewchange.go#L130-L155)):
   The new leader collects `Qc` NewViewMsgs, extracts the highest genericQC, and
   proposes.  Since the post-GST network delivers messages within Δ, the leader
   receives enough messages within bounded time.

4. **Pipeline advancement** ([pipeline.go](file:///d:/GO/d-hotstuff/internal/consensus/pipeline.go)):
   Pipelined phases ensure that each successful view produces one committed block,
   amortizing the three-phase cost to O(1) per round.

### Tests

- [TestLiveness](file:///d:/GO/d-hotstuff/tests/simulation/property_test.go) — sets GST, submits 5
  commands, advances clock by 10×viewTimeout, verifies all commands are delivered
  to honest replicas.
- [TestConsecutiveLeaderFailures](file:///d:/GO/d-hotstuff/tests/integration/adversary_test.go) — fc
  consecutive leader failures → progress within fc+1 view changes.

---

## Theorem 13 — Consistent Delivery (Validity)

> **Statement**: If a correct client c submits a value v, then c eventually
> receives fc+1 consistent replies from honest replicas.

### Implementation

Theorem 13 is a composite property built from:

- **Agreement** (Theorem 10): all honest replicas deliver the same value.
- **Integrity** (Theorem 11): each replica delivers it at most once.
- **Liveness** (Theorem 12): it is eventually delivered.

The client-side logic (future `cmd/client/main.go`) will:
1. Submit the request to the current leader.
2. Collect reply messages from replicas.
3. Wait until `fc + 1` replies with matching results arrive.
4. Return the result to the application.

The [Replier](file:///d:/GO/d-hotstuff/internal/consensus/deliver.go#L36-L45) interface is the
server-side half of this — called once per executed request to send the result
back to the client.

### Tests

- [TestByzantineLeaderEquivocation](file:///d:/GO/d-hotstuff/tests/integration/adversary_test.go) — verifies
  that Byzantine equivocation does not prevent honest replicas from agreeing and
  eventually delivering the correct value.
- [TestByzantineHistoryResponse](file:///d:/GO/d-hotstuff/tests/integration/adversary_test.go) — verifies that
  fabricated responses from Byzantine replicas are rejected.

---

## Complexity Analysis

### Best Case: O(n²)

One successful view costs O(n²) total authenticator transmissions:

```
Leader broadcasts proposal:     n  messages
Replicas send votes to leader:  n  messages, each containing 1 signature
Leader broadcasts QC:           n  messages
                                ────────
Total:                          3n messages, QC carries n signatures
                                → O(n) sigs × O(n) recipients = O(n²)
```

This is implemented in [dhotstuff.go propose()](file:///d:/GO/d-hotstuff/internal/consensus/dhotstuff.go)
(broadcast) and [HandleVote()](file:///d:/GO/d-hotstuff/internal/consensus/dhotstuff.go) (accumulate + CreateQC).

### Worst Case: O(n³)

When `fc` consecutive leaders are Byzantine, the protocol needs O(n) view changes
before reaching an honest leader:

```
O(n) view changes × O(n²) per view change = O(n³)
```

Each view change sends a NewViewMsg containing a QC with O(n) signatures to the
next leader.  With O(n) replicas performing this: O(n) × O(n) = O(n²) per view.
Over O(n) views: O(n³).

This is documented in [viewchange.go](file:///d:/GO/d-hotstuff/internal/consensus/viewchange.go#L1-L16)
and benchmarked in [BenchmarkViewChangeOverhead](file:///d:/GO/d-hotstuff/internal/metrics/bench_test.go).

### Improvement over Dyno

D-HotStuff improves over Dyno by a factor of O(n) in view-change cost:

| Protocol | View Change Cost | Reason |
|----------|-----------------|--------|
| Dyno | O(n³) per view change | PBFT-style all-to-all communication |
| D-HotStuff | O(n²) per view change | HotStuff linear view change (send QC to next leader) |

Over O(n) consecutive failures:

| Protocol | Total Cost | Formula |
|----------|-----------|---------|
| Dyno | O(n⁴) | O(n) failures × O(n³) per failure |
| D-HotStuff | O(n³) | O(n) failures × O(n²) per failure |

This O(n) improvement comes from HotStuff's key insight: the view-change message
is a single QC (O(n) signatures) sent to one leader, rather than an all-to-all
exchange.  The [OnTimeout](file:///d:/GO/d-hotstuff/internal/consensus/viewchange.go#L94-L122)
implementation sends exactly one `NewViewMsg` to the next leader, not to all replicas.
