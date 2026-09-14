# APKey_Hide

> 消除 APatch / KernelPatch 鉴权路径上「用户参数页被额外读取」侧信道的独立 KPM 模块。
> `name=APKey_Hide` · `author=Lun.` · `license=MIT` · Android arm64（KP / APatch / FolkPatch 之上）

---

## 主要被检测原因

这条侧信道之所以成立，**唯一的原因是 KernelPatch 的 `compat_strncpy_from_user()` 在不走 nofault 原语的内核上会回退（fallback）到普通 `strncpy_from_user()`**——一次会真正触发缺页的用户内存读。

KP 的 supercall 鉴权路径正是用这个函数去读「superkey 指针」所指向的内存

---

## 一、检测原理

> 参考：春秋检测文档 <https://mingzun09.github.io/Chunqiu-Detector-Problem-solution/#/File/Doc/ksu_kp_sidechannel_zh>

### 1.1 载体：KernelPatch 自建的 syscall 45

KernelPatch 注册了一个自己的系统调用 `__NR_supercall = 45`（arm64 上 45 恰好是 `truncate` 的编号，所以 magic 路径叫 `/system/bin/truncate`）。APatch 管理器就是通过它向 KernelPatch 发起鉴权请求、下发 `su` / KPM 装载等命令。

它的入口是 `supercall.c: before()`。本工程编译依据的是 KernelPatch 0.13.2（其 `SUPERCALL_HELLO_ECHO` 为 `"hello1158"`，与设备 dmesg 输出一致）：

```c
static void before(hook_fargs6_t *args, void *udata)
{
    ...
    if (has_preset_superkey()) {
        const char __user *key_user = (const char __user)syscall_argn(args, 0);  // x0 = superkey 指针
        char key[MAX_KEY_LEN];                                                   // 128
        long len = compat_strncpy_from_user(key, key_user, MAX_KEY_LEN);          // ← 先读 x0
        if (len <= 0) return;
        ...
    }
    if (is_trusted_manager_uid(uid)) { ... } else if (is_su_allow_uid(uid)) { ... }
    if (!is_trusted_caller) return;

    long ver_xx_cmd = (long)syscall_argn(args, 1);                                // x1 低 16 位 = cmd
    long cmd = ver_xx_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;                     // ← 后判 cmd
    ...
}
```

**两件事决定了这条侧信道能不能成立**：

1. 鉴权请求天然带一个"由调用者给出的用户态指针"（x0 = superkey 指针），**内核会去解引用它**；
2. 这个解引用**发生在 cmd 范围判断之前**——`x1` 取什么值都拦不住它。

顺序换过代。0.10 / 0.12 一代是**反的**：先 `if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;`，再读密钥。那种顺序下 §1.3 的负 `x1` 会在门控处被挡掉，根本读不到 x0；本机这一代不存在这个挡板。

### 1.2 ★ 根因：compat 的 nofault 回退

`kernel/patch/common/utils.c`：

```c
long compat_strncpy_from_user(char *dest, const char __user *src, long count)
{
    if (kver > VERSION(6, 7, 0)) {
        kfunc_call(strncpy_from_user_nofault, dest, src, count);   // 6.8+ 才走这里
        kfunc_call(strncpy_from_unsafe_user, dest, src, count);
    }

    if (kfunc(strncpy_from_user)) {                                // ★ 回退：会真正缺页
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

（`kfunc_call(f, ...)` 展开为 `if (kf_f) return kf_f(...);`，即"有则用并立刻返回"。）

关键就在 `kver > VERSION(6, 7, 0)` 这道**版本门**：在 ≤ 6.7.0 的内核上，KP **连试都不试** nofault，直接落到 `strncpy_from_user()`。挡在这一步的是 KP 自己的版本判断，不是原语缺失——`strncpy_from_user_nofault()` 在 6.1 的 `mm/maccess.c` 里就已经存在（6.8 同文件、同实现）。

两者的差别只有一行 `pagefault_disable()`：

```c
/* mm/maccess.c */
long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    pagefault_disable();                                   // ★ 缺页不再被"处理"
    ret = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    ...
}
```

于是同一次读，后果完全不同：

| 读法                                      | 遇到"未换入的匿名页"时                  | 副作用                                  |
| --------------------------------------- | ---------------------------- | ------------------------------------ |
| `strncpy_from_user`（**回退路径**）            | 正常走缺页处理 → 分配零页 → 读成功返回全 0    | 该页 **被换入**；`min_flt` +1；VMA `Referenced` 置位 |
| `strncpy_from_user_nofault`（6.8+）        | `pagefault_disable()` 下失败 → 返回 `-EFAULT` | 不分配页，页表/计数器**零变化**                    |

**⇒ 这条侧信道是"回退"制造出来的，不是 KernelPatch 的设计意图。** KP 在 > 6.7.0 的内核上走 nofault，就不再暴露它；本机 4.19 落在回退分支上，才有得测。KPM 改不了 KP 的这条路径，也无法让本机 KP 去试那个它主动跳过的 nofault，所以只能从**调用侧**介入（见 §二）。

### 1.3 靶点：为什么 `x1` 为负是唯一干净的判据

原生 `do_sys_truncate()`：

```c
static long do_sys_truncate(const char __user *pathname, loff_t length)
{
        if (length < 0)                  /* 长度检查在 user_path_at/getname **之前** */
                return -EINVAL;          /* ⇒ 干净内核一个字节都不读 pathname */
        error = user_path_at(AT_FDCWD, pathname, ...);
```

同一个 `x1` 寄存器，在原生 truncate 里是 `length`，在 KP 里是 `cmd` 的低 16 位：

| 调用                                    | 干净内核                   | 打了 KP（本机顺序）                          |
| ------------------------------------- | ---------------------- | ----------------------------------- |
| `syscall(45, x0=懒页, x1<0)`            | 长度检查提前返回 `-EINVAL`，**不读 x0** | `before()` 读 x0（superkey 指针）⇒ 该页被换入 |
| `syscall(45, x0=懒页, x1≥0)`            | `getname()` 会读 x0       | 同样会读 ⇒ **无差异**                      |
| `syscall(45, key串, x1=0x1010, x2=懒页)` | 只读 x0                  | 鉴权通过后 `call_su` → `memdup_user` 读 x2 |

⇒ **侧信道只存在于 `x1 < 0` 这一种参数布局**：此时 x0 上发生的任何读取 / 换入都只可能来自 KP 的 superkey 读取（§1.1 的顺序是它的前提）。`x1 ≥ 0` 两边都读，检测器无法据此区分内核，因此那里必须**保持原生语义**（否则会破坏 `Read control` 对照）。

errno 本身就把"有没有读路径"区分开了：`x1 < 0` 走长度检查、返回 `-EINVAL`；`x1 ≥ 0` 才进 `user_path_at` / `getname`，路径读不到时返回 `-EFAULT`。同一个坏指针、两种 errno，正是"负 length 提前返回、压根没读 path"的体现。

### 1.4 三条判定通道

检测器（`com.chunqiunativecheck`，uid 10254）与公开文档涉及下面三条口径。它们针对同一个鉴权路径，可互相印证：

**① 懒分配页探测**

> 懒分配：用户态 `mmap` 一块匿名页后**从不触碰** → VMA 有了，PTE 还没有，物理页尚未分配。

把它的地址当作 superkey 指针放进 x0 发起鉴权请求，调用后看该页是否被映射到物理内存：

| 结果      | 含义          |
| ------- | ----------- |
| `0 → 0` | 内核没读过它      |
| `0 → 1` | 内核读了一次 ⇒ KP |

**② 鉴权时延探测**

检测器拟定一个**在范围内**的 cmd 与一个**不在范围内**的 cmd，分别发起多次、累加求和使比值稳定：

| 比值    | 判定   |
| ----- | ---- |
| `> 2` | KP 存在 |
| `≈ 1` | 无 KP |

这条口径成立的前提是"cmd 越界会提前返回"，即 §1.1 里**门控在密钥读取之前**的那一代 KP。本机走不到这个差异：密钥先读，且对非受信任调用者而言密钥不匹配就已经 `return`，cmd 取值影响不到执行路径 ⇒ 比值恒 `≈ 1`，该口径在本机不成立（见 §二 L4）。

**③ 系统调用参数页被额外读取（对照法）**

以"系统调用参数页被额外读取"为判据的侧信道。检测器把目标调用的参数/缓冲区放在一块受监控的用户页上，测量调用前后该页被内核读取的页数：

| 对照                              | 期望读数                           | 说明                          |
| ------------------------------- | ------------------------------ | --------------------------- |
| `No-read control`（内核按语义不应读该页） | `0 → 0 kB`                     | 基线                          |
| `Read control`（内核应当读该页）         | `0 → 4 kB`                     | 正对照，证明探针本身可用                |
| `Target call`（目标调用）             | 出现 `0 → 4 kB, unexpected read` | 内核在该 syscall 路径上**多读了一次用户内存** ⇒ 该路径被内核补丁额外处理 |

该条目同时会输出 `Argument layouts`（内核读取系统调用参数的寄存器布局探测）、多轮一致性 `Consistency: n/n`、`Page size`，以及 `Probe duration`（秒级，采样较重）。

> 与 `Abnormal Environment` 的关系：两者针对同一类"鉴权路径"侧信道。仓库里的 KSU/APatch 侧信道说明描述的是"**懒分配页是否被映射**"与"**鉴权时延比值**"两种口径；本条是按**页读取量做对照**的实现，属同一思路的不同变体，可互相印证。
>
> 口径换算：报告同时给出页数与 `Page size`（4096 B），所以 `0 → 4 kB` 就是 `0 → 1` 页。判据是"被监控页是否被换入 / 是否发生缺页"（等价 `min_flt` 增量），**不是 `smaps` 的 `Referenced` 口径**——被监控页是 `mmap` 后从未触碰的懒分配页，而 `Read control` 用一次"本来就该读该页"的调用作正对照。

---

## 二、对策

根因既然在"那次读会触发缺页"，对策就只有两条路：**(a) 让那次读不发生**，或 **(b) 把它换成不触发缺页的读**。(b) 需要改动 KP 自身（KPM 做不到，也无法让本机 KP 去试它主动跳过的 nofault），所以本模块走 (a)。

### L0｜槽位前置（必须最外层）

KP 的 supercall 钩子走 `hook_syscalln()` → `fp_wrap_syscalln()` → `fp_hook_wrap()`，在 hook 链的**槽 0**；链上的 before 回调按索引 `0→N` 顺序执行——晚装的挂钩只会落到槽 1，也就是**在 KP 之后**执行，等发现问题时页已经被读了。

因此本模块用框架 `fp_hook()` **直接接管 `sys_call_table[45]` 槽位**，把 KP 的链 transit 保存为 backup，正常路径原样调用（KP 功能零回归）。

### L1｜核心短路：让那次读根本不发生

```c
if (x1 < 0 && 调用者不在受信任白名单)  return -EINVAL;
```

- **返回原生 errno**：干净内核对负 `length` 给的就是 `-EINVAL`，所以返回值**逐字节一致**，不会因"返回值不同"形成新指纹（返回 `-EFAULT` 反而是破绽）。
- **一个字节都不读 x0**：不建 PTE、不置 AF、不触发缺页，`min_flt` / `Referenced` 全无变化 ⇒ 通道 ① 与 ③ 同时失效。
- **不依赖线性映射标定、不依赖页表遍历**：`x1 < 0` 是纯寄存器判定，任何内核 / KP 变体上都成立，也不会因标定失败而静默失效。
- **零回归**：`x1 ≥ 0` 时完全不干预（原生 `getname` 本来就读 x0，KP 的读不增加任何新信号）⇒ `Read control` 对照不受影响；真实程序 `truncate(path, 负长度)` 在干净内核上同样是 `-EINVAL`，行为一致。

### L4｜时延均衡（对应通道 ②；默认关闭）

通道 ② 只在"cmd 越界会让 KP 提前返回"时才有信号。本机 KP 的 cmd 门控在密钥读取**之后**，且对非受信任调用者而言密钥不匹配就已在门控之前 `return`——cmd 取值影响不到执行路径，范围内 / 范围外两条路径同源 ⇒ **比值恒 `≈ 1`，本机该口径不成立**，故 L4 默认关闭（`eq=0`）。

它只为**门控在前**的那一代 KP 保留：那里越界分支会提前返回，与正常分支开销差明显。打开后只在越界分支补一次等长（`APK_EQ_LEN = 128`，等于 KP 的 `MAX_KEY_LEN`）的读取，让两条分支对齐。读取对象仍是 x0——该分支只在 `x1 ≥ 0` 时可达，而原生 `getname` 本来就会读 x0，所以这次读不产生任何新信号。

### 身份过滤：只对"该管的人"生效

| 门               | 依据                                                                | 作用                                                                    |
| --------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| **受信任 uid 白名单** | KP 导出的 `current_uid()`（KP 内部用运行时探测的 `task_struct→cred→uid` 偏移实现，模块侧无需硬编码偏移） | 默认 `{0}`；root / 管理器 / su 一律放行，普通应用 uid 才会被干预。`ctl0 allow=` 可调 |
| **管理器形态识别**     | 实测管理器 supercall 的 `x1 = 0xD0811581_XXXX`：**正数、高 32 位带自有非签名**，cmd 在低 16 位  | `x1` 高 32 位非 0 的调用**永不干预**，只做"读寄存器 + 原样转发"                             |
| **窗口 + 本任务绑定**  | 只有本模块负责的那次 syscall 正在执行、且就是当前任务时才成立                               | 让可选守卫（G1/G2/G3）的作用域严格受限                                               |

> 补充事实：`su` 走的是 execve 魔法路径，**根本不调用 `syscall(45)`**，因此与 `x1 < 0` 这条判定天然无关。

### 可选守卫 G1/G2/G3（默认全部关闭）

用于覆盖**其它**参数布局（x2 / x3 上的 `memdup_user`、KP 的字符串原语等）。每个都要求**四道门同时成立**：窗口内 + `apk_win_task == current` + 非受信任 uid + 遍历已被 oracle 证实。

- **G1**：`memdup_user` —— 源页不可无痕访问时返回**全 0 缓冲**（匿名懒页真实内容就是全 0，与真读该页逐字节等价，但不动页表、不产生缺页）；
- **G2**：`compat_strncpy_from_user` —— 源页不可无痕访问时返回 0（正是 KP `if (len <= 0) return;` 的"读不到"分支）；
- **G3**：`compat_copy_to_user` —— 写方向加固（默认关，误伤合法"尚未触碰的接收缓冲"有回归风险）。

**默认全部关闭**有两层原因：① 真实靶点（`x1 < 0`）已由 L1 覆盖，不需要它们；② 关掉后模块**不安装任何全局原语钩子**，系统级足迹只剩 `sys_call_table[45]` 一个槽位。需要覆盖别的布局时：先 `allow=0,<管理器uid>`，再 `g1=1` / `g2=1`。

### fail-open：宁可不生效，绝不误伤

页表遍历是否可信，用一条**必然成立的事实**来验证：运行中任务的 PC 页**必然 present**。若遍历把它判成"不可用"，说明标定或参数有误 ⇒ 立刻下线所有依赖遍历的守卫（`walk=0`），之后任何判定失败都走"原样调用原实现"。合法客户端因此不可能被本模块改变行为。

> 这条门不是理论洁癖。G2 曾无窗口、无身份限制地对全系统 `compat_strncpy_from_user` 做判断，把"合法但尚未换入的懒分配页"判成不可用并直接返回 0 ⇒ 静默吃掉 KP 自己 execve 鉴权链上的密钥 / 路径读取，表现为"检测项没了、管理器与 su 也一起废了"（同一根因）。四道门就是由此而来。

---

## 三、构建 / 部署 / 运行时接口

```text
构建：  build.ps1                        # 产出 bin/APKey_Hide_<ver>_debug.kpm 与 _release.kpm
上机：  build.ps1 -Deploy -ReleaseOnly    # 构建 + 清设备陈旧副本 + 推唯一文件到 /sdcard/Download
收尾：  build.ps1 -CleanDevice            # ★加载完成之后★ 再执行，清空公共目录里的副本
```

模块身份与产物名由源码宏 `KPM_NAME` / `KPM_VERSION` 自动派生；构建依赖 KernelPatch 源码目录（`KP_DIR`，默认 `KernelPatch_temp`）。

运行时接口（`ksud kpm ctl0 APKey_Hide <cmd>`）：

| 命令                                        | 作用                                                                |
| ----------------------------------------- | ----------------------------------------------------------------- |
| `status` / `info`（含空命令与未识别命令）             | 一行状态：`neg`（L1 命中次数）、`x1n`、`ver`（遍历是否已证实）、`alw`、`walk`、`mair`、各守卫计数 |
| `allow=0` / `allow=0,2000` / `allow=none` | 受信任 uid 白名单                                                       |
| `x1neg=0\|1`                              | L1 核心短路开关                                                         |
| `g1=0\|1` `g2=0\|1` `g3=0\|1`             | 各可选守卫开关（默认 0）                                                     |
| `eq=0\|1`                                 | 时延均衡（默认 0）                                                        |
| `latch=0\|1`                              | 槽位前置开关（关掉即整模块待机）                                                  |
| `recal`                                   | 重新标定（同时把 `ver` 归零，守卫待重新证实）                                        |
| `walk=<hex>`                              | 手动指定线性映射偏移（排障用）                                                   |

---

## 四、边界

- 判据依赖「arm64 上 `nr 45 = truncate`」且「`do_sys_truncate` 的长度检查在读路径之前」——4.x ~ 6.x 一致，本机 4.19 已确认；换内核需按同样方式复测。
- 靶点还依赖「密钥读取先于 cmd 门控」这一代 KP 顺序（§1.1）；若换成门控在前的那一代，`x1 < 0` 会被门控挡掉，需改用 `x1` 低 16 位落在 `0x1000`–`0x1200` 的负值。
- 本机实测 KP **不挂 32 位 compat 表**（compat nr45 是 `brk`，全组无反应），故本模块只处理原生入口。
- 依赖 KP 导出符号 `current_uid`（以及 hook 框架的 `fp_hook` / `fp_unhook` 等）；若某个 KP 变体未导出，模块会**加载失败**而不会带着错误状态运行。
- G1/G2/G3 依赖线性映射标定与 `bits[47:12]` 掩码，且默认关闭；**L1 不依赖它们**。
- 已知不覆盖：`x2` / `x3` 布局（需显式打开 G1）、写方向口径（G3）、32 位 compat 入口。
- 内核 > 6.7.0 时 KP 自己走 nofault，通道 ① 与 ③ 本就不成立；L1 只对 `x1 < 0` 且非受信任 uid 生效，而合法调用者的 `x1` 恒为正（见 §二 身份过滤），不受影响。

---

## 五、文件

| 文件                                     | 说明                                        |
| -------------------------------------- | ----------------------------------------- |
| `APKey_Hide.c`                         | 模块全部实现（单文件，含分区注释）                         |
| `Makefile` / `build.ps1`               | 构建（debug/release）与一键部署                    |
