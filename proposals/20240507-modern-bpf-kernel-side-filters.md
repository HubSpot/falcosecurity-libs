# Adding Kernel-side filtering to the Modern BPF driver
## Summary

For deployments of Falco on larger instances, we need to be able to cut down on the number of noisy events coming from the driver as the rules engine being single-threaded becomes a bottleneck.

There exists the feature to toggle individual syscalls, but more granularity here would allow for more capable deployments monitoring all relevent syscalls that can also filter out sources of concentrated noise.

## Motivation

There are users of Falco deploying to hosts with 128+ CPUs where syscall throughput is too high for the system to sustain consistently. These hosts are especially susceptable to a bursty workload capable of causing a large percentage of events to be dropped.

Here, being able to filter out the noisy/bursty workloads individually is preferable to disabling the collection of entire syscalls.

## Goals

- Define a flexible config schema for these filters
- Implement the filters to be as performant as possible without introducing means of circumventing detection

## Non-Goals

- Design/implement filters for other driver types

## The Plan

### Review Filter Schema v1

The initial implementation of the filter config schema is as follows:

```
filters:
  - syscall: 257 # syscall number for `openat` on `x86_64` 
    arg: 1 # file path
    prefixes: ["/proc", "/sys/fs/cgroup"]
```

Each entry in the YAML list contains:
- The syscall number for the target archetecture.
- The arg number for the syscall. This is expected to be a `char *`.
- The prefixes to match and filter against inside the kernel hook.

#### Performance

We were able to deploy this patch on our infrastrucure and collect the following data. All of this is aggregated over a 4 day window.

Event rate (`scap.evts_rate_sec`:
```
count      1022425.000000 (number of metric samples)
mean         78169.513609
std          56479.322696
min              0.000000
50%          71634.525317
90%         139310.344902
99%         260659.990578
99.9%       565055.582845
99.99%      734383.889699
99.999%     779872.462636
max         824091.991662
```

Event drop rate (`scap.n_drops_perc`):
Vanilla Falco `0.36.2`:
```
count      1022425.000000 (number of metric samples)
mean             0.282009
std              3.849407
min              0.000000
50%              0.000000
90%              0.000016
99%              1.781471
99.9%           77.758152
99.99%          94.549621
99.999%         97.712998
max             99.290935
```
Falco `0.37.0` with our patch filter filtering out 6 commonly seen path prefixes for file open events: 
```
count      104192.000000 (number of metric samples)
mean            0.472717
std             2.702165
min             0.000000
50%             0.000000
90%             0.593645
99%             9.937187
99.9%          46.086308
99.99%         71.471973
99.999%        76.030033
max            76.692583
```

To summarize, it looks like we get drastically better worst-case performance at the cost of slightly worst 90-99th performance. 

This doesn't factor in other changes in Falco made between `0.36.2` and `0.37.0`, but it's likely not too significant looking at the changelog.

### Make necessary improvements

To make this feature production ready, we should include more guardrails to improve the UX if used improperly. This includes being able to specify syscalls by name instead of by syscall number.

As for performance, it may be worth looking into how we can optimize this further. Putting fully qualified filenames into a map for a constant time check in the kernel hook would be preferable for performance, but a lot harder for users to maintain than supplying prefixes. 

### Next Steps

1. Gather feeback on the current implementation in regard to how we can improve filtering performance while keeping usability.
2. Improve the UX of this feature and add documentation for how to use it

