# APKey_Hide
[点我看中文版本](README-CN.md)
> An independent KPM module that eliminates the side channel of "**system call argument pages being additionally read**" on the APatch / KernelPatch authentication path.
> `name=APKey_Hide` · `author=Lun.` · `license=MIT` · Platform: Android arm64 (on top of KP / APatch / FolkPatch)

---

## 1. Where the side channel is

KernelPatch creates its own system call `__NR_supercall = 45` (on arm64, 45 happens to be the number of `truncate`).
Its authentication entry point `supercall.c: before()` does:

```
ukey = syscall_argn(args, 0);                     // x0 = the superkey pointer given by the caller
cmd  = syscall_argn(args, 1) & 0xFFFF;            // lower 16 bits of x1 = command number
len  = compat_strncpy_from_user(key, ukey, 128);  // ← reads x0: pulls in the page pointed to by ukey
```

Whereas the semantics of the native `truncate` are:

```c
static long do_sys_truncate(const char __user *pathname, loff_t length)
{
        if (length < 0)                 /* length check happens **before** user_path_at/getname */
                return -EINVAL;         /* ⇒ a clean kernel does not read a single byte of pathname for a negative length */
        error = user_path_at(AT_FDCWD, pathname, ...);
```

⇒ Thus there exists a difference that **only appears once KernelPatch is installed**:

| Call | Clean kernel | With KP installed |
|---|---|---|
| `syscall(45, x0=some page, x1=negative)` | The length check returns early with `-EINVAL`, **x0 is not read** | `before()` reads x0 (the superkey pointer) ⇒ the page is faulted in / AF is set |
| `syscall(45, x0=some page, x1=positive)` | `getname()` will read x0 | It also reads it ⇒ **no difference** |

The detector passes the address of a "lazily allocated page / unreadable page" as the superkey pointer into `x0`, then uses a negative `loff_t` as `length`
(i.e., the same register is both `length` and the low bits of `cmd`), and after the call checks whether that page has been faulted in — if it has been faulted in, KP is judged to be present.
The side channel exists only in the `x1<0` argument layout: in this case, any read that happens on x0 can only come from KP.

---

## 2. How to solve it

### L0 | Slot pre-emption (must be before KP)

KP's supercall hook is installed via `hook_syscalln()` → `fp_hook_wrap()` at **slot 0** of the hook chain, and the before callbacks on the chain execute in index order `0→N` — a hook installed later will only land in slot 1, i.e., **after KP**,
and by the time it notices, the page has already been read. Therefore this module uses the framework's `fp_hook()` to **directly take over the `sys_call_table[45]` slot**,
saving KP's chain transit as a backup and calling it as-is on the normal path (zero regression to KP functionality).

### L1 | Core short-circuit (the step that eliminates the side channel)

```
if (x1 < 0 && caller is not in the trusted whitelist)  return -EINVAL;
```

* **Returns the native errno**: a clean kernel gives exactly `-EINVAL` for a negative length, so the return value is byte-for-byte identical,
  and no new fingerprint is formed from "a different return value" (returning `-EFAULT` would instead be a giveaway).
* **Does not read a single byte of x0**: no PTE is created, no AF is set, no page fault is triggered, and `min_flt` / `Referenced` remain unchanged.
* **Does not depend on linear-map calibration or page-table walking**: `x1<0` is a pure register test, so it holds on any kernel / KP variant,
  and it will not silently fail because calibration failed.
* **Zero regression**: when `x1≥0` there is no intervention at all (the native `getname` already reads x0, so KP's read adds no new signal);
  a real program calling `truncate(path, negative length)` on a clean kernel also gets `-EINVAL`, so behavior is consistent.

### Filter: only takes effect for "the people it should manage"

| Gate | Basis | Effect |
|---|---|---|
| **Trusted uid whitelist** | KP-exported `current_uid()` (KP internally uses a runtime-probed `task_struct→cred→uid` offset, so the module side needs no hard-coded offsets) | Default `{0}`; root / manager / su are always allowed, and only ordinary app uids are intervened with. Adjustable via `ctl0 allow=` |
| **Manager-shape recognition** | Measured manager supercall `x1 = 0xD0811581_XXXX`: **positive, with its own non-signature in the upper 32 bits**, command number in the lower 16 bits | Calls whose upper 32 bits of `x1` are non-zero **never open a window and are never intervened with**, only "read the register + forward as-is" |
| **Window + same-task binding** | Holds only when the syscall that this module is responsible for is currently executing and it is the current task | Strictly limits the scope of the optional guards (G1/G2/G3) |

> Additional fact: `su` goes through the execve magic path and **does not call `syscall(45)` at all**, so it is naturally unrelated to the `x1<0` criterion.

### Optional guards G1/G2/G3 (all disabled by default)

Used to cover **other** argument layouts (`memdup_user` on `x2` / `x3`, KP's string primitives, etc.).
Each requires **all four gates to hold simultaneously**: within the window + `apk_win_task == current` + non-trusted uid + walking already proven by the oracle.

* G1: `memdup_user` — when the source page cannot be accessed without a trace, return an **all-zero buffer** (the real contents of an anonymous lazy page are all zeros, byte-for-byte equivalent to actually reading that page, but without touching the page table or causing a page fault);
* G2: `compat_strncpy_from_user` — when the source page cannot be accessed without a trace, return 0 (exactly KP's `if (len <= 0) return;` "could not read" branch);
* G3: `compat_copy_to_user` — write-direction hardening (off by default; accidentally affecting a legitimate "not-yet-touched receive buffer" carries regression risk).

**The reason all are disabled by default has two layers**: ① the real target (`x1<0`) is already covered by L1, so they are not needed;
② once disabled, the module **installs no global primitive hooks at all**, and the only system-level footprint left is the single `sys_call_table[45]` slot.
When other layouts need to be covered: first `allow=0,<manager uid>`, then `g1=1` / `g2=1`.

### fail-open: prefer not taking effect over causing harm

Whether page-table walking is trustworthy is verified using a **fact that must hold**: the PC page of a running task is **necessarily present**.
If walking judges it as "unusable", then the calibration or arguments are wrong ⇒ immediately take all guards that depend on walking offline (`walk=0`),
and after that any failed judgment falls back to "call the original implementation as-is". Legitimate clients therefore cannot have their behavior changed by this module.

---

## 3. Implementation constraints (stealth and stability)

* Uses only natural architectural means: `MRS` to read system registers, read-only page-table walking, `copy_from_kernel_nofault`, framework hook primitives;
  **no custom inline hooks, no creds tampering, no dmesg clearing, no `call_usermodehelper`**.
* **Does not create proc / sysfs nodes, does not write files, does not open the network**; the release build produces no `printk` output
  (logging exists only in debug builds, controlled by the compile-time switch `APK_DEBUG_LOG`).
* The physical address mask precisely limits `bits[47:12]` according to `shift` (consistent with the LH driver), and Device-attribute pages (upper half-byte of MAIR is 0)
  are always refused for linear-map reads, avoiding bus violations.
* Unloading is fully reversible: first turn off the feature switches → drain in-flight callbacks → remove the slot → drain again, avoiding callbacks stepping into reclaimed `.text`.

---

## 4. Deployment and interface

```text
Build:   build.ps1                     # produces bin/APKey_Hide_<ver>_debug.kpm and _release.kpm
Deploy:  build.ps1 -Deploy -ReleaseOnly   # build + clear stale copies on the device + push the unique file to /sdcard/Download
Cleanup: build.ps1 -CleanDevice           # ★after loading is complete★ run this to clear the copies in the public directory
```

The module identity and artifact names are automatically derived from the source macros `KPM_NAME` / `KPM_VERSION`.

Runtime interface (`ksud kpm ctl0 APKey_Hide <cmd>`):

| Command | Effect |
|---|---|
| `status` / `info` | One-line status: `neg` (L1 hit count), `x1n`, `ver` (whether walking has been proven), `alw`, `walk`, `mair`, guard counters |
| `allow=0` / `allow=0,2000` / `allow=none` | Trusted uid whitelist |
| `x1neg=0\|1` | L1 core short-circuit switch |
| `g1=0\|1` `g2=0\|1` `g3=0\|1` | Individual optional guard switches (default 0) |
| `latch=0\|1` | Slot pre-emption switch (turning it off puts the whole module on standby) |
| `recal` | Recalibrate (also resets `ver` to zero, and guards await re-proof) |

---

## 5. Compatibility and boundaries

* The criterion depends on "on arm64 `nr 45 = truncate`" and "`do_sys_truncate`'s length check precedes the read path" —
  consistent from 4.x to 6.x, confirmed on this machine's 4.19; changing kernels requires retesting in the same way.
* On this machine, KP was measured **not to hook the 32-bit compat table** (compat nr45 is `brk`, and the whole group shows no reaction), so this module handles only the native entry.
* Depends on the KP-exported symbol `current_uid` (as well as the hook framework's `fp_hook` / `fp_unhook`, etc.);
  if some KP variant does not export them, the module will **fail to load** rather than run with an incorrect state.
* G1/G2/G3 depend on linear-map calibration and the `bits[47:12]` mask, and are disabled by default; L1 does not depend on them.
* Known not covered: `x2`/`x3` layouts (requires explicitly enabling G1), the write-direction convention (G3), and the 32-bit compat entry.

---

## 6. Files

| File | Description |
|---|---|
| `APKey_Hide.c` | The module's entire implementation (single file, with section comments) |
| `Makefile` / `build.ps1` | Build (debug/release) and one-click deployment |
