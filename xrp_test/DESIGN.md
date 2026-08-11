# XRP B-tree Lookup Pushdown for WiredTiger

A point lookup whose lower tree levels are not cached normally costs one
kernel round trip per level: read a page, parse it in userspace, issue the
next dependent read. This feature pushes the uncached suffix of the
traversal into the NVMe completion path with XRP: WiredTiger walks the
resident prefix of the tree in memory, and at the first disk-only page it
hands the kernel the search key and the child's block address. A BPF program
then parses each completed 512-byte page in the completion handler, chooses
the next child, resubmits the read from interrupt context, searches the leaf,
and returns only the verdict and value through a scratch buffer. No traversed
page is ever published into the WiredTiger cache.

## Correctness properties

The integration is sound because of five properties, most of which
WiredTiger already provides and the design merely has to preserve.

**P1, cache prefix.** If a page is resident, every ancestor needed to route
to it is resident. WiredTiger maintains this because internal pages are not
evicted while they have in-memory children. Consequence: once the in-memory
descent reaches a disk-only reference, no page below that point holds newer
state in memory, so the disk image below it is the current routing for that
subtree.

**P2, fresh reads come from the resident path.** Committed updates that are
not yet reconciled to disk live in in-memory structures attached to resident
pages. By P1, a search for such a key reaches that in-memory state before it
can encounter a disk-only reference, so the pushdown never fires below fresh
state. A write therefore never needs to coordinate with XRP; it only needs to
dirty pages, which makes them resident, which retracts the pushdown boundary
above them.

**P3, result-only completion.** The kernel returns found or not-found plus
the value bytes; it never returns pages, and the cursor is left unpositioned.
This is what removes all coexistence problems: XRP requests own no cache
state, compete with no normal read for page ownership, and can run
concurrently with normal reads of the same blocks. The costs are that the
resident prefix is never grown by an XRP read (see P6) and that positioned
cursor operations (next, prev) are out of scope.

**P4, immutable disk blocks.** WiredTiger never overwrites a live block in
place; reconciliation writes new blocks and retires old ones. An in-flight
XRP chain holding a block address therefore reads either the current bytes of
a still-live block or a retired-but-not-reused block, which is a consistent
older image. The remaining hazard, reuse of a retired block during a chain's
microsecond-scale window, is narrowed by checkpoint pinning of previous-
checkpoint blocks and by the kernel aborting any chain whose file extent
mapping changed mid-flight. A formal guarantee still wants the design doc's
retire-delay, which is not implemented; billions of self-validating reads
under concurrent write churn found no violation.

**P5, fail-safe fallback.** The BPF program handles a deliberately narrow
format subset (row store, 512-byte blocks, plain and short keys and values,
no prefix compression, overflow items, dictionaries, or prepared updates)
and refuses everything else; the kernel aborts chains on any mapping
inconsistency; and the userspace wrapper treats any of these, plus a
sentinel that detects the request never having run as XRP at all, as one
answer: retry this lookup through the normal read path. Fallback is
per-lookup and unconditional, so every hazard degrades to performance, never
to a wrong answer.

## Performance properties

**P6, sampled cache repair.** Because of P3 the resident prefix can only
shrink: an evicted internal page is never reloaded by XRP lookups, so chains
silently grow longer forever. The fix is cache sampling: one in N eligible
lookups (default 100) takes the normal read path, publishing and touching
internal pages so the prefix regrows and stays hot. Sampling doubles as a
continuous cross-check of XRP results against the normal path on live
traffic.

**P7, cache admission bypass is the dominant win.** The expected benefit was
saving kernel round trips, worth about 1.2x single-threaded and 1.9x at 32
threads on Optane in a cache-free apples-to-apples harness. The larger,
initially unexpected benefit is that result-only reads never compete for
buffer-pool admission: under cache pressure with many threads, the normal
path serializes on eviction (drafted application threads, hazard scans), a
cost measured at 43 percent of per-operation time and not removable by
eviction tuning, while XRP reads scale with the device. End to end this
makes the pushdown worth up to 5.3x at the cached-prefix operating point.

**P8, the fallback rate is the health metric.** The kernel invalidates
in-flight chains whenever the file's extent map version changes, and the
version is currently whole-file, so unrelated allocations kill chains. Write
churn, and even the pushdown's own fallback and sampling traffic, sustain an
8 to 26 percent abort rate depending on workload. Tracking aborted chains
per successful chain is the single best indicator of how much headroom the
integration is leaving; per-extent versioning in the kernel is the top
improvement.

## Kernel contract

The XRP kernel must provide: resubmission by file-logical offset with
per-hop extent translation and version checking; registration of the
requesting file's descriptor and inode on the request (absent for plain
read_xrp in the WIP kernel, restored by a one-line fix); and abort semantics
that surface as a failed read. The BPF program must name the file descriptor
for each resubmission and bound its own depth. O_DIRECT is mandatory, which
in WiredTiger terms means direct I/O for data files, memory mapping off, and
buffer alignment matching the 512-byte allocation size.

## Results snapshot

Optane P5800X, 10M keys, six levels, uniform random point lookups, 32
threads, values validated on every read: pushdown 1.13M to 1.67M ops/s
across cache sizes from 16MB to 128MB versus 211k to 1.10M ops/s for the
normal path, with soundness clean across roughly 1.4 billion validated reads
on two machines, including 50/50 read/write stress with checkpoints every
ten seconds.

## Open items

Retire-delay for block reuse (P4 formal gap); per-extent version granularity
in the kernel (P8); publishing internal pages from the completion path as an
alternative to sampling (P6); positioned cursors and range scans; values
larger than the scratch buffer; modern WiredTiger versions, whose reworked
eviction may narrow P7.
