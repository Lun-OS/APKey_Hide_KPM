[点我看中文](README-CN.md)

# APKey_Hide

> An independent KPM module that eliminates the side channel of "**user argument pages being additionally read**" on the APatch / KernelPatch authentication path.
> `name=APKey_Hide` · `author=Lun.` · `license=MIT` · Android arm64 (on top of KP / APatch / FolkPatch)

---

## Main Reason for Being Detected

The **sole reason** this side channel exists is that KernelPatch's `compat_strncpy_from_user()` falls back to the ordinary `strncpy_from_user()` on kernels that do not use the nofault primitive—a user-memory read that really does trigger a page fault.

KP's supercall authentication path uses exactly this function to read the memory pointed to by the "superkey pointer".

---

## 1. Detection Principle

> Reference: Chunqiu Detector documentation <https://mingzun09.github.io/Chunqiu-Detector-Problem-solution/#/File/Doc/ksu_kp_sidechannel_zh>

### 1.1 Carrier: KernelPatch's self-created syscall 45

KernelPatch registers its own system call `__NR_supercall = 45` (on arm64, 45 happens to be the number of `truncate`, so the magic path is called `/system/bin/truncate`). The APatch manager uses it to send authentication requests to KernelPatch and to issue commands such as `su` / KPM loading.

Its entry point is `supercall.c: before()`. This project is compiled against KernelPatch 0.13.2 (whose `SUPERCALL_HELLO_ECHO` is `"hello1158"`, consistent with the device's dmesg output):

```c
static void before(hook_fargs6_t *args, void *udata)
{
    ...
    if (has_preset_superkey()) {
        const char __user *key_user = (const char __user)syscall_argn(args, 0);  // x0 = superkey pointer
        char key[MAX_KEY_LEN];                                                   // 128
        long len = compat_strncpy_from_user(key, key_user, MAX_KEY_LEN);          // ← reads x0 first
        if (len <= 0) return;
        ...
    }
    if (is_trusted_manager_uid(uid)) { ... } else if (is_su_allow_uid(uid)) { ... }
    if (!is_trusted_caller) return;

    long ver_xx_cmd = (long)syscall_argn(args, 1);                                // lower 16 bits of x1 = cmd
    long cmd = ver_xx_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;                     // ← cmd is checked later
    ...
}
```

**Two things determine whether this side channel can exist**:

1. An authentication request naturally carries a "user-space pointer supplied by the caller" (x0 = superkey pointer), and **the kernel will dereference it**;
2. This dereference **happens before the cmd range check**—no value of `x1` can stop it.

The order has changed across generations. The 0.10 / 0.12 generation was the **opposite**: first `if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;`, then read the key. Under that order, the negative `x1` of §1.3 would be blocked at the gate, and x0 would not be read at all; that barrier does not exist in the generation on this machine.

### 1.2 ★ Root cause: the compat nofault fallback

`kernel/patch/common/utils.c`:

```c
long compat_strncpy_from_user(char *dest, const char __user *src, long count)
{
    if (kver > VERSION(6, 7, 0)) {
        kfunc_call(strncpy_from_user_nofault, dest, src, count);   // only 6.8+ goes here
        kfunc_call(strncpy_from_unsafe_user, dest, src, count);
    }

    if (kfunc(strncpy_from_user)) {                                // ★ fallback: really faults
        long rc = kfunc(strncpy_from_user)(dest, src, count);
        if (rc >= count) { rc = count; dest[rc - 1] = '\0'; }
        else if (rc > 0) { rc++; }
        return rc;
    }

    kfunc_call(strncpy_from_user_nofault, dest, src, count);
    kfunc_call(strncpy_from_unsafe_user, dest, src, count);
    return 0;
}
```

(`kfunc_call(f, ...)` expands to `if (kf_f) return kf_f(...);`, i.e., "if available, use it and return immediately".)

The key is the **version gate** `kver > VERSION(6, 7, 0)`: on kernels ≤ 6.7.0, KP **does not even try** nofault and falls straight through to `strncpy_from_user()`. What blocks this step is KP's own version check, not the absence of the primitive—`strncpy_from_user_nofault()` already existed in 6.1's `mm/maccess.c` (same file, same implementation in 6.8).

The only difference between the two is one line, `pagefault_disable()`:

```c
/* mm/maccess.c */
long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    pagefault_disable();                                   // ★ page faults are no longer "handled"
    ret = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    ...
}
```

Thus the same read has completely different consequences:

| Read method                                | When encountering a "not-yet-faulted-in anonymous page" | Side effect                                                |
| ------------------------------------------ | -------------------------------------------------------- | ---------------------------------------------------------- |
| `strncpy_from_user` (**fallback path**)    | Goes through normal page-fault handling → allocates a zero page → read succeeds and returns all zeros | The page **is faulted in**; `min_flt` +1; VMA `Referenced` is set |
| `strncpy_from_user_nofault` (6.8+)         | Fails under `pagefault_disable()` → returns `-EFAULT`    | No page is allocated; page table / counters **change by zero** |

**⇒ This side channel is created by the "fallback", not by KernelPatch's design intent.** On kernels > 6.7.0, KP uses nofault and no longer exposes it; this machine's 4.19 falls into the fallback branch, which is why it can be measured. A KPM cannot change this path inside KP, nor can it make the local KP try the nofault it deliberately skips, so intervention is only possible from the **caller side** (see §2).

### 1.3 Target: why a negative `x1` is the only clean criterion

Native `do_sys_truncate()`:

```c
static long do_sys_truncate(const char __user *pathname, loff_t length)
{
        if (length < 0)                  /* length check happens **before** user_path_at/getname */
                return -EINVAL;          /* ⇒ a clean kernel does not read a single byte of pathname */
        error = user_path_at(AT_FDCWD, pathname, ...);
```

The same `x1` register is `length` in native truncate and the lower 16 bits of `cmd` in KP:

| Call                                    | Clean kernel                   | With KP installed (local order)                          |
| --------------------------------------- | ------------------------------ | -------------------------------------------------------- |
| `syscall(45, x0=lazy page, x1<0)`       | The length check returns early with `-EINVAL`, **x0 is not read** | `before()` reads x0 (superkey pointer) ⇒ the page is faulted in |
| `syscall(45, x0=lazy page, x1≥0)`       | `getname()` will read x0       | It also reads it ⇒ **no difference**                     |
| `syscall(45, key string, x1=0x1010, x2=lazy page)` | Only reads x0         | After authentication passes, `call_su` → `memdup_user` reads x2 |

⇒ **The side channel exists only in the `x1 < 0` argument layout**: in this case, any read / fault-in that happens on x0 can only come from KP's superkey read (the order in §1.1 is its precondition). When `x1 ≥ 0`, both sides read, so the detector cannot distinguish the kernel on that basis, and therefore the native semantics must be **preserved** there (otherwise the `Read control` comparison would be broken).

errno itself distinguishes "whether there is a read path": `x1 < 0` goes through the length check and returns `-EINVAL`; only `x1 ≥ 0` enters `user_path_at` / `getname`, which returns `-EFAULT` when the path cannot be read. The same bad pointer with two different errnos is precisely the manifestation of "a negative length returns early and the path is never read".

### 1.4 Three detection channels

The detector (`com.chunqiunativecheck`, uid 10254) and the public documentation involve the following three criteria. They target the same authentication path and can corroborate each other:

**① Lazy-allocation page probe**

> Lazy allocation: after the user space `mmap`s an anonymous page, it is **never touched** → the VMA exists, but the PTE does not, and no physical page has been allocated yet.

Put its address into x0 as the superkey pointer and initiate an authentication request; after the call, check whether the page has been mapped to physical memory:

| Result  | Meaning                  |
| ------- | ------------------------ |
| `0 → 0` | The kernel did not read it |
| `0 → 1` | The kernel read it once ⇒ KP |

**② Authentication latency probe**

The detector prepares one cmd **within range** and one cmd **out of range**, initiates each many times, and accumulates the sums so that the ratio is stable:

| Ratio   | Verdict   |
| ------- | --------- |
| `> 2`   | KP exists |
| `≈ 1`   | No KP     |

The premise of this criterion is that "an out-of-range cmd returns early", i.e., the KP generation in §1.1 where **the gate is before the key read**. This machine cannot reach that difference: the key is read first, and for an untrusted caller a key mismatch already causes `return` before the gate, so the cmd value cannot affect the execution path ⇒ the ratio is always `≈ 1`, and this criterion does not hold on this machine (see §2 L4).

**③ System call argument pages being additionally read (comparison method)**

A side channel whose criterion is "system call argument pages being additionally read". The detector places the target call's argument / buffer on a monitored user page and measures how many pages the kernel reads from that page before and after the call:

| Comparison                            | Expected reading                | Description                                                  |
| ------------------------------------- | ------------------------------- | ------------------------------------------------------------ |
| `No-read control` (the kernel should not read that page semantically) | `0 → 0 kB` | Baseline                                                     |
| `Read control` (the kernel should read that page) | `0 → 4 kB` | Positive control, proving the probe itself works             |
| `Target call` (the target call)       | `0 → 4 kB, unexpected read` appears | The kernel **read user memory one extra time** on that syscall path ⇒ that path is additionally handled by a kernel patch |

This item also outputs `Argument layouts` (register-layout probing of how the kernel reads system call arguments), multi-round consistency `Consistency: n/n`, `Page size`, and `Probe duration` (on the order of seconds; sampling is relatively heavy).

> Relationship to `Abnormal Environment`: both target the same class of "authentication path" side channel. The KSU/APatch side-channel description in the repository describes two criteria: "**whether a lazily allocated page is mapped**" and "**the authentication latency ratio**"; this item is an implementation based on **comparison of page read amounts**, a different variant of the same idea, and the two can corroborate each other.
>
> Unit conversion: the report gives both the number of pages and `Page size` (4096 B), so `0 → 4 kB` is `0 → 1` page. The criterion is "whether the monitored page is faulted in / whether a page fault occurs" (equivalent to the `min_flt` increment), **not the `Referenced` criterion of `smaps`**—the monitored page is a lazily allocated page that has never been touched after `mmap`, while `Read control` uses a call that "should have read that page anyway" as a positive control.

---

## 2. Countermeasures

Since the root cause is that "that read triggers a page fault", there are only two possible approaches: **(a) make that read not happen**, or **(b) replace it with a read that does not trigger a page fault**. (b) requires modifying KP itself (a KPM cannot do it, nor can it make the local KP try the nofault it deliberately skips), so this module takes (a).

### L0 | Slot pre-emption (must be the outermost layer)

KP's supercall hook goes through `hook_syscalln()` → `fp_wrap_syscalln()` → `fp_hook_wrap()`, at **slot 0** of the hook chain; the before callbacks on the chain execute in index order `0→N`—a hook installed later will only land in slot 1, i.e., **after KP**, and by the time the problem is noticed, the page has already been read.

Therefore this module uses the framework's `fp_hook()` to **directly take over the `sys_call_table[45]` slot**, saving KP's chain transit as a backup and calling it as-is on the normal path (zero regression to KP functionality).

### L1 | Core short-circuit: make that read not happen at all

```c
if (x1 < 0 && caller is not in the trusted whitelist)  return -EINVAL;
```

- **Returns the native errno**: a clean kernel gives exactly `-EINVAL` for a negative `length`, so the return value is **byte-for-byte identical**, and no new fingerprint is formed from "a different return value" (returning `-EFAULT` would instead be a giveaway).
- **Does not read a single byte of x0**: no PTE is created, no AF is set, no page fault is triggered, and `min_flt` / `Referenced` remain unchanged ⇒ channels ① and ③ are both disabled.
- **Does not depend on linear-map calibration or page-table walking**: `x1 < 0` is a pure register test, so it holds on any kernel / KP variant, and it will not silently fail because calibration failed.
- **Zero regression**: when `x1 ≥ 0` there is no intervention at all (the native `getname` already reads x0, so KP's read adds no new signal) ⇒ the `Read control` comparison is unaffected; a real program calling `truncate(path, negative length)` on a clean kernel also gets `-EINVAL`, so behavior is consistent.

### L4 | Latency equalization (corresponds to channel ②; disabled by default)

Channel ② only has a signal when "an out-of-range cmd causes KP to return early". In the local KP, the cmd gate is **after** the key read, and for an untrusted caller a key mismatch already causes `return` before the gate—the cmd value cannot affect the execution path, and the in-range and out-of-range paths share the same source ⇒ **the ratio is always `≈ 1`, and this criterion does not hold on this machine**, so L4 is disabled by default (`eq=0`).

It is retained only for the KP generation where **the gate comes first**: there, the out-of-range branch returns early and has an obvious cost difference from the normal branch. When enabled, it only adds one read of equal length (`APK_EQ_LEN = 128`, equal to KP's `MAX_KEY_LEN`) on the out-of-range branch, aligning the two branches. The read target is still x0—that branch is only reachable when `x1 ≥ 0`, and the native `getname` would read x0 anyway, so this read produces no new signal.

### Identity filtering: only takes effect for "the people it should manage"

| Gate                        | Basis                                                                 | Effect                                                                 |
| --------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Trusted uid whitelist**   | KP-exported `current_uid()` (KP internally uses a runtime-probed `task_struct→cred→uid` offset, so the module side needs no hard-coded offsets) | Default `{0}`; root / manager / su are always allowed, and only ordinary app uids are intervened with. Adjustable via `ctl0 allow=` |
| **Manager-shape recognition** | Measured manager supercall `x1 = 0xD0811581_XXXX`: **positive, with its own non-signature in the upper 32 bits**, cmd in the lower 16 bits | Calls whose upper 32 bits of `x1` are non-zero are **never intervened with**, only "read the register + forward as-is" |
| **Window + same-task binding** | Holds only when the syscall that this module is responsible for is currently executing and it is the current task | Strictly limits the scope of the optional guards (G1/G2/G3) |

> Additional fact: `su` goes through the execve magic path and **does not call `syscall(45)` at all**, so it is naturally unrelated to the `x1 < 0` criterion.

### Optional guards G1/G2/G3 (all disabled by default)

Used to cover **other** argument layouts (`memdup_user` on x2 / x3, KP's string primitives, etc.). Each requires **all four gates to hold simultaneously**: within the window + `apk_win_task == current` + non-trusted uid + walking already proven by the oracle.

- **G1**: `memdup_user` — when the source page cannot be accessed without a trace, return an **all-zero buffer** (the real contents of an anonymous lazy page are all zeros, byte-for-byte equivalent to actually reading that page, but without touching the page table or causing a page fault);
- **G2**: `compat_strncpy_from_user` — when the source page cannot be accessed without a trace, return 0 (exactly KP's `if (len <= 0) return;` "could not read" branch);
- **G3**: `compat_copy_to_user` — write-direction hardening (off by default; accidentally affecting a legitimate "not-yet-touched receive buffer" carries regression risk).

**All disabled by default for two reasons**: ① the real target (`x1 < 0`) is already covered by L1, so they are not needed; ② once disabled, the module **installs no global primitive hooks at all**, and the only system-level footprint left is the single `sys_call_table[45]` slot. When other layouts need to be covered: first `allow=0,<manager uid>`, then `g1=1` / `g2=1`.

### fail-open: prefer not taking effect over causing harm

Whether page-table walking is trustworthy is verified using a **fact that must hold**: the PC page of a running task is **necessarily present**. If walking judges it as "unusable", then the calibration or arguments are wrong ⇒ immediately take all guards that depend on walking offline (`walk=0`), and after that any failed judgment falls back to "call the original implementation as-is". Legitimate clients therefore cannot have their behavior changed by this module.

> This gate is not theoretical nitpicking. G2 once judged the whole system's `compat_strncpy_from_user` with no window and no identity restriction, treating a "legitimate but not-yet-faulted-in lazily allocated page" as unusable and directly returning 0 ⇒ silently swallowing KP's own key / path reads in the execve authentication chain, manifesting as "the detection item is gone, and the manager and su are also broken together" (the same root cause). The four gates came about because of this.

---

## 3. Build / Deploy / Runtime Interface

```text
Build:   build.ps1                        # produces bin/APKey_Hide_<ver>_debug.kpm and _release.kpm
Deploy:  build.ps1 -Deploy -ReleaseOnly    # build + clear stale copies on the device + push the unique file to /sdcard/Download
Cleanup: build.ps1 -CleanDevice            # ★after loading is complete★ run this to clear the copies in the public directory
```

The module identity and artifact names are automatically derived from the source macros `KPM_NAME` / `KPM_VERSION`; the build depends on the KernelPatch source directory (`KP_DIR`, default `KernelPatch_temp`).

Runtime interface (`ksud kpm ctl0 APKey_Hide <cmd>`):

| Command                                    | Effect                                                                |
| ------------------------------------------ | --------------------------------------------------------------------- |
| `status` / `info` (including empty and unrecognized commands) | One-line status: `neg` (L1 hit count), `x1n`, `ver` (whether walking has been proven), `alw`, `walk`, `mair`, guard counters |
| `allow=0` / `allow=0,2000` / `allow=none` | Trusted uid whitelist                                                 |
| `x1neg=0\|1`                              | L1 core short-circuit switch                                          |
| `g1=0\|1` `g2=0\|1` `g3=0\|1`             | Individual optional guard switches (default 0)                        |
| `eq=0\|1`                                 | Latency equalization (default 0)                                      |
| `latch=0\|1`                              | Slot pre-emption switch (turning it off puts the whole module on standby) |
| `recal`                                   | Recalibrate (also resets `ver` to zero, and guards await re-proof)    |
| `walk=<hex>`                              | Manually specify the linear-map offset (for troubleshooting)          |

---

## 4. Boundaries

- The criterion depends on "on arm64 `nr 45 = truncate`" and "`do_sys_truncate`'s length check precedes the read path"—consistent from 4.x to 6.x, confirmed on this machine's 4.19; changing kernels requires retesting in the same way.
- The target also depends on the KP generation order "key read before cmd gate" (§1.1); if switched to the generation where the gate comes first, `x1 < 0` will be blocked by the gate, and one must instead use a negative value whose lower 16 bits fall in `0x1000`–`0x1200`.
- On this machine, KP was measured **not to hook the 32-bit compat table** (compat nr45 is `brk`, and the whole group shows no reaction), so this module handles only the native entry.
- Depends on the KP-exported symbol `current_uid` (as well as the hook framework's `fp_hook` / `fp_unhook`, etc.); if some KP variant does not export them, the module will **fail to load** rather than run with an incorrect state.
- G1/G2/G3 depend on linear-map calibration and the `bits[47:12]` mask, and are disabled by default; **L1 does not depend on them**.
- Known not covered: `x2` / `x3` layouts (requires explicitly enabling G1), the write-direction convention (G3), and the 32-bit compat entry.
- On kernels > 6.7.0, KP itself uses nofault, so channels ① and ③ do not hold in the first place; L1 only takes effect for `x1 < 0` and non-trusted uids, while a legitimate caller's `x1` is always positive (see §2 Identity filtering), so it is unaffected.

---

## 5. Files

| File                                   | Description                                        |
| -------------------------------------- | -------------------------------------------------- |
| `APKey_Hide.c`                         | The module's entire implementation (single file, with section comments) |
| `Makefile` / `build.ps1`               | Build (debug/release) and one-click deployment     |
