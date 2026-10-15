# Detection fixes: the detector's view, and what "replicate built-in" costs

Read this after the code: the fixes themselves live in upstream `inforcqb/susfs4ksu-lkm`
commits `9bedfb7` (sus_dirent.c, susfs_opath.c) and `309902c` (open_redirect fdinfo ids),
and their rationale is in the file headers and commit messages there. This file is the map
from the other side - what a detector measured on a real device, why each fix exists, what
remains detectable, and what full built-in equivalence costs. Measured on a Pixel 8, GKI
`6.1.162-android14` (WildKernels, built-in susfs), with `susfs_guard_lkm` loaded on top,
probed by an unprivileged app (`uid=10393`).

## The two oracles the detector shipped with

A zero-permission app (no root, no special UIDs) measured two things on the module as it
shipped:

**1. The getdents64 buffer race.** The listing rewrite in `sus_path_filter()` runs after
the kernel has already copied the full `/proc` listing into the caller's buffer, and
rewrites the chain in place to drop hidden entries. Its failure paths were fail-open:

- a uaccess fault with nothing yet written back returned the **unfiltered** `count` - the
  entire listing, hidden names included;
- with bytes already compacted, it returned `written` while the tail scrub raced the same
  page; the detector's mprotect toggler (flipping the buffer `PROT_NONE`/`PROT_READ` in a
  loop for a 5-second budget) can win that race, and the dropped records' names stay
  readable **past the returned length** - the detector scans, it does not honour lengths.

Leaked capture from the device: recovered bytes at `+0x633` of the buffer containing
`...partitions...susfs_path...timer_list...device-tree...` - the module's own control
node names, out of a listing that officially never contained them.

There is a third window the toggle is not even needed for: **while the listing syscall is
in flight**, the caller's other threads can read the buffer (it is their own mapped
memory) and see filldir64 write the unfiltered chain. One reader thread spinning next to
one getdents64 call sees everything; no race, no fault injection, just concurrency.

**2. The O_PATH/fstat inconsistency.** The LSM hooks answer `stat` and `open` on a hidden
node with `ENOENT`, but `open(..., O_PATH)` never calls them (`do_dentry_open()` returns
before `security_file_open()` for `FMODE_PATH` opens, and the O_PATH walk calls no
permission hook). So `open(O_PATH)` succeeded and handed back a live descriptor the
`fstat` on which answered `ENOENT` - an interface disagreement that is impossible for a
genuine proc entry, which is the whole oracle. `susfs_opath.c` was written to close this
and post-checks every open - but on this device it fired 96 times and denied 0 times
(`/proc/susfs_opath`: `hidden=96 deny=0 err=96`).

### Root cause of the O_PATH failure: the fd-removal primitive changed shape at 6.1

Measured across the trees the module builds against:

| tree | primitive |
|---|---|
| android13-5.10 / android13-5.15 | `int close_fd_get_file(unsigned fd, struct file **res)` |
| android14-6.1 / android15-6.6 | `struct file *close_fd_get_file(unsigned fd)` |
| android16-6.12 / android17-6.18 | `struct file *file_close_fd(unsigned fd)` |

The layer was written against the 5.15 shape. On 6.1+ the file pointer lands in `x0`,
reads as a nonzero "failure" int, the reference `pick_file()` already moved to the caller
is never `fput()`ed, and the syscall still answers success with a descriptor that was
**just removed from the table**. Ninety-six hidden opens, ninety-six leaked references,
ninety-six stranded descriptors - the layer produced the exact state it exists to close.
A by-name resolution step cannot see this: the symbol resolves fine on every tree. This
is the lesson worth keeping: **a presence check is not a signature check**, and every
version-gated helper in this module needs its shape verified per tree, not its name.

The same lesson in the other direction cost two DDK matrix rounds while this analysis was
underway: `filldir_t` itself changed - its "keep going" return went from `int 0` to
`bool true` at 6.1 (sus_dirent.c encodes that as `SD_RET/SD_GO/SD_STOP`). Upstream's
`9bedfb7` fixes the O_PATH shapes at runtime (`opath_close_fd_resolved()`) instead of
compile-time gates, which also survives a backport that carries only one of the shapes.

## What the fixes do (upstream `9bedfb7`)

1. **`sus_dirent.c` (new, prefilter on by default)** - the structural fix, and the answer
   to "replicate built-in with an LKM": runs `iterate_dir()` with its own filldir that
   never emits a hidden name. A hidden name is never written to user memory at all, so
   both windows above close **by construction** - there is nothing left to race. It also
   removes the all-hidden placeholder record, because the walk simply continues inside
   the same call, which is what the kernel does anyway. Shared by native getdents64,
   compat getdents64 and compat getdents, so no ABI falls back to the post-hoc scrub.
2. **`susfs_opath.c`** - the fd-removal prototype is now resolved per shape, and the
   deny path `fput()`s what the file*-returning shapes hand it. The 96/0/96 state is
   closed on every tree.
3. **`susfs_kstat.c`** - the syscall-entry dispatch that drives the prefilter for every
   getdents ABI.

After the fix set, the expected detector answers on this device: the race probe **clean**
(`/proc` names never enter the buffer), the O_PATH probe **clean** (the open itself
answers `ENOENT`, consistent with a nonexistent node) - while the module's hiding still
works, because the prefilter asks the same table the stat layers ask.

## Other detectable behaviour found while auditing (unfixed, low priority)

- **`i_mode` relaxation to 0777** (`sus_path_relax_mode()`): a rule's file mode is
  rewritten globally so DAC cannot answer before the LSM layer. Root always sees it; an
  app sees it on any rule-targeted file it owns (the gate exempts the owner from hiding,
  but not from the mode rewrite). A detector that owns a file and watches for `0777`
  appearing on it sees the module. Upstream avoids this by patching namei directly;
  an LKM cannot, and the EACCES-vs-ENOENT inconsistency on the other side is worse.
- **d_off gaps** after compaction: the chain skips the dropped entries' offsets. Weak -
  deletions do the same on real filesystems. (The all-hidden placeholder record the old
  rewrite left - `d_ino = 0`, empty name, no real filesystem emits it - is gone with the
  prefilter, which never emits one.)
- **Module presence**: self-hidden from `/proc/modules` content (verified - the module
  is invisible there even to the grep that looks for it), from kallsyms, and its control
  nodes answer `ENOENT` to every non-root caller. The remaining tell is behavioural
  (this file).

## "Replicate built-in with an LKM" - the honest map

Built-in susfs hides by never generating the evidence: it skips entries inside
`filldir64()` and answers inside namei, so no user-visible state ever disagrees. An LKM
cannot patch those two functions (static, LTO-inlined, compiled into the kernel image),
so every equivalence it achieves is a substitute at a hook point it *can* reach:

| built-in mechanism | LKM substitute | equivalence |
|---|---|---|
| skip inside `filldir64()` | run `iterate_dir()` with a non-emitting filldir (sus_dirent prefilter) | **exact, all filesystems, all getdents ABIs**: nothing user-visible ever disagrees |
| namei answers `ENOENT` at lookup | LSM `inode_getattr`/`inode_permission` insertions | **near-exact**: every path-based syscall is covered; error codes match upstream's |
| `open` refuses before fd install | syscall-table post-check (O_PATH layer) | **exact now**: the fd is taken away and `ENOENT` returned |
| no `/proc/susfs_*` nodes when hidden | self-protect rules + LSM `ENOENT` | **exact for non-root callers** |
| no module (nothing to hide from `/proc/modules`) | self-hiding from modules/kallsyms | adequate; presence remains behaviourally inferable, as this file shows |

What an LKM can never fully erase: the LSM hooks are *insertions ahead of SELinux* and
the syscall-table entries are *replaced pointers* - both invisible to a non-root caller,
both fingerprintable by root (table entries pointing at module text, hook dispatch order).
That is the correct threat-model boundary: this module's job is to disappear from apps,
not from the operator.
