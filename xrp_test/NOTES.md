# XRP B-tree pushdown: fallback behavior and mitigation notes

Status (2026-07-30): pushdown implemented and sound. Two 15-minute stress runs
(32 threads, checkpoint every 10s, 16MB cache, 1M keys, self-validating
values): 50/50 read/write passed with ~26% of XRP attempts falling back, 99/1
passed with 0.099% falling back. Zero wrong values, lost keys, phantoms, or
kernel incidents across 138M validated XRP reads.

## Why chains abort under write load

The kernel validates every XRP resubmission hop by translating the next file
offset through the inode's XRP extent tree and comparing a version number
recorded at the previous hop. The version is bumped on any ext4 extent-status
change for the file and is one version for the whole file (per-extent
versioning is noted as unimplemented in xrp_sync_ext4_extent). Any block
allocation during WiredTiger reconciliation therefore kills every in-flight
chain, even chains reading old, stable blocks whose mapping never moved. For
WiredTiger this check is almost always a false positive: the data file only
grows and live blocks are never remapped.

WiredTiger writes the file only during reconciliation: checkpoints and dirty
eviction. At 50/50 the cache cannot hold the dirty set, dirty eviction writes
continuously, so the version churns continuously (26% aborts). At 99/1 the
writes collapse into the checkpoint window and the file is quiescent in
between (0.099%).

Each abort is doubly expensive: the failed XRP attempt (syscall plus partial
read chain) plus the full normal-path lookup it falls back to.

## Mitigations, in suggested order

1. Preallocate the data file (block manager). File growth is the dominant
   churn source: every new block allocation edits the extent map. If the file
   is fallocated ahead in large chunks (and extents materialized as written),
   steady-state reconciliation lands inside already-mapped extents and the
   version stops moving even under heavy writes. Small change, attacks the
   root cause, no read-path impact.

2. Circuit breaker in the read path. Gate the pushdown eligibility check in
   __wt_btcur_search: after k fallbacks in a window, disable XRP for the tree
   for T ms, then probe. Converges to XRP-off during write storms and XRP-on
   otherwise, without knowing checkpoint internals. A simpler static variant:
   skip the pushdown while WT_BTREE_SYNCING is set or the tree reconciled in
   the last N ms.

3. Batch checkpoints. Fewer, larger checkpoints shrink the number of hot
   windows; composes with 1 and 2.

4. Kernel range versioning. Replace the whole-file version with per-extent or
   per-range versions so appends do not invalidate chains over stable blocks.
   Cleanest result, biggest lift. The one behavior whole-file versioning
   accidentally covers is truncation and hole punching, which WiredTiger does
   not do to live data files.

## Cache bypass: the third benefit of result-only pushdown

Headline (verified): 100% uniform read, 10M keys (depth 6), 16MB cache
(internals resident, leaves cold), 32 threads, Optane P5800X: XRP 1,128k
ops/s at 2.49 hops/chain vs baseline 211k ops/s at ~2 page-ins/op, a 5.3x
win. The XRP side runs the device at its measured 512B ceiling (fio: 2.68M
IOPS; the run sustained ~2.5M) while the baseline is software-limited at
~420k IOPS by per-page instantiation and eviction work. Fallback tax in that
run: 9.1%. Single-thread at the same point: 15.5 vs 22.0 us/op (1.4x).

Full 32-thread cache sweep (same workload, ops/s XRP vs off, XRP hops,
fallback): 1MB 190.8k vs 28.3k (3.11 hops, 13.9%); 16MB 1128k vs 211k (2.49,
9.1%); 32MB 1294k vs 241k (2.13, 9.2%); 64MB 1443k vs 390k (1.71, 9.1%);
128MB 1674k vs 1102k (1.13, 7.9%). XRP throughput rises smoothly as the
resident prefix deepens; the baseline is hypersensitive to cache size around
the eviction-pressure boundary (390k at 64MB to 1102k at 128MB). The gap
narrows toward parity as the cache approaches the dataset size. Fallbacks sit
at a steady 8-9% regardless of cache size, consistent with version-bump
self-interference proportional to normal-path read traffic; at 1MB the
fallback tax is amplified because each fallback lands in the thrashing
normal path, which also drags the XRP-side number down there.

Do not quote the 1MB-cache 32-thread comparisons (28.3k ops/s baseline on
Optane, 12.0k on Micron) as the XRP win: a 600MB working set on a 1MB cache
puts WiredTiger into cache-full thrash where the baseline collapses below its
own single-thread throughput, and adding eviction threads makes it worse
(28.3k to 11.0k). That regime says more about WiredTiger's cache-full
protocol than about XRP. XRP does sidestep the thrash entirely (190.8k ops/s
there), which is a real property, but the fair comparison point is a cache
sized to the internal levels.

## Eviction tuning does not remove the interference

Baseline at 16MB/32 threads (211k ops/s, 63us/op app-eviction stall) with
every applicable knob: eviction=(threads_min=16,threads_max=16) collapses it
6.5x to 32.3k ops/s with 515us/op stall (16 eviction threads plus 32 workers
fight over the same tiny cache, hazard scans and eviction-pass locking
serialize everything); eviction_target=60,eviction_trigger=90 changes
nothing (the cache sits pinned at trigger regardless, app threads always get
drafted); cursor read_once=true changes nothing (victim selection is not the
bottleneck, admission is). Conclusion: at this pressure point the eviction
cost is structural in the WT 4.4 cache-full protocol, not a tuning artifact;
the only effective remedies are more cache (0.6us/op at 128MB) or not
admitting the pages at all, which is what result-only XRP does. Caveat:
modern WiredTiger has reworked eviction and may narrow this gap.

## Deconfounded mechanism comparison (no cache on either side)

user_lookup/xrp_lookup bench modes run identical full-depth chains (5 hops,
1M-key tree, uniform random, values validated) with zero cache management on
both sides, isolating the submission mechanism: syscalls per hop vs in-kernel
resubmission. Optane, 60s cells, zero errors: 1 thread 35.0k vs 42.0k ops/s
(1.20x), 8 threads 218.9k vs 291.5k (1.33x), 32 threads 395.3k vs 750.8k
(1.90x). XRP at 32 threads implies ~3.75M device reads/s, above what
fio/libaio could drive (2.68M), because resubmissions bypass the block-layer
submission cost entirely.

Putting the decomposition together for the 32-thread uniform-read workload:
pure mechanism 1.9x; add WT page instantiation on the baseline (128MB
eviction-free in-WT comparison) 1.5x observed there; add eviction contention
(16-32MB) 5.3-5.4x. So roughly: mechanism ~1.9x, cache admission and
eviction bypass contributes the remaining ~2.8x under cache pressure, minus
the 8-9% fallback tax.

## Related design gaps still open

- Extent-reuse delay from the design doc is not implemented; checkpoint
  pinning plus parse validation plus the kernel version check closed every
  observable hole in testing, but a formal argument still wants the delay.
- Result-only XRP never republishes pages, so the resident prefix decays
  without help; cache sampling (WT_BPF_BTREE_SAMPLE, default 1 in 100) keeps
  it warm and is also a continuous cross-check of XRP against the normal
  path.
