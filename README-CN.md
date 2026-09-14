# APKey_Hide

> 消除 APatch / KernelPatch 鉴权路径上「**系统调用参数页被额外读取**」侧信道的独立 KPM 模块。
> `name=APKey_Hide` · `author=Lun.` · `license=MIT` · 平台：Android arm64（KP / APatch / FolkPatch 之上）

---

## 一、侧信道在哪

KernelPatch 自建了一个系统调用 `__NR_supercall = 45`（arm64 上 45 恰好是 `truncate` 的编号）。
它的鉴权入口 `supercall.c: before()` 会：

```
ukey = syscall_argn(args, 0);                     // x0 = 调用者给的 superkey 指针
cmd  = syscall_argn(args, 1) & 0xFFFF;            // x1 低 16 位 = 命令号
len  = compat_strncpy_from_user(key, ukey, 128);  // ← 读 x0：把 ukey 指向的页读进来
```

而原生 `truncate` 的语义是：

```c
static long do_sys_truncate(const char __user *pathname, loff_t length)
{
        if (length < 0)                 /* 长度检查在 user_path_at/getname **之前** */
                return -EINVAL;         /* ⇒ 干净内核对负 length 一个字节都不读 pathname */
        error = user_path_at(AT_FDCWD, pathname, ...);
```

⇒ 于是存在一个**只有打了 KernelPatch 才出现**的差异：

| 调用 | 干净内核 | 打了 KP |
|---|---|---|
| `syscall(45, x0=某页, x1=负值)` | 长度检查提前返回 `-EINVAL`，**不读 x0** | `before()` 读 x0（superkey 指针）⇒ 该页被换入 / AF 被置位 |
| `syscall(45, x0=某页, x1=正值)` | `getname()` 会读 x0 | 同样会读 ⇒ **无差异** |

检测器把「懒分配页 / 不可读页」的地址当 superkey 指针传进 `x0`，再用负的 `loff_t` 当 `length`
（即同一个寄存器既是 `length` 又是 `cmd` 低位），调用后检查该页是否被换入 —— 被换入即判定 KP 存在。
侧信道只存在于 `x1<0` 这一种参数布局：此时 x0 上发生的任何读取都只能来自 KP。

---

## 二、怎么解决

### L0｜槽位前置（必须在 KP 之前）

KP 的 supercall 钩子用 `hook_syscalln()` → `fp_hook_wrap()` 装在 hook 链的**槽 0**，而链上的
before 回调按索引 `0→N` 顺序执行 —— 晚装的挂钩只会落到槽 1，也就是**在 KP 之后**执行，
等发现时页已经被读了。因此本模块用框架 `fp_hook()` **直接接管 `sys_call_table[45]` 槽位**，
把 KP 的链 transit 保存为 backup，正常路径原样调用（KP 功能零回归）。

### L1｜核心短路（消除侧信道的那一步）

```
if (x1 < 0 && 调用者不在受信任白名单)  return -EINVAL;
```

* **返回原生 errno**：干净内核对负 length 给的就是 `-EINVAL`，所以返回值逐字节一致，
  不会因为"返回值不同"形成新的指纹（返回 `-EFAULT` 反而是破绽）。
* **一个字节都不读 x0**：不建 PTE、不置 AF、不触发缺页，`min_flt` / `Referenced` 全无变化。
* **不依赖线性映射标定、不依赖页表遍历**：`x1<0` 是纯寄存器判定，因此任何内核 / KP 变体上都成立，
  也不会因为标定失败而静默失效。
* **零回归**：`x1≥0` 时完全不干预（原生 `getname` 本来就读 x0，KP 的读不增加任何新信号）；
  真实程序调用 `truncate(path, 负长度)` 在干净内核上同样是 `-EINVAL`，行为一致。

### 过滤器：只对"该管的人"生效

| 门 | 依据 | 作用 |
|---|---|---|
| **受信任 uid 白名单** | KP 导出的 `current_uid()`（KP 内部用运行时探测的 `task_struct→cred→uid` 偏移实现，模块侧无需任何硬编码偏移） | 默认 `{0}`；root / 管理器 / su 一律放行，普通应用 uid 才会被干预。可用 `ctl0 allow=` 调整 |
| **管理器形态识别** | 实测管理器 supercall 的 `x1 = 0xD0811581_XXXX`：**正数、高 32 位带自有非签名**，命令号在低 16 位 | `x1` 高 32 位非 0 的调用**永不开窗、永不干预**，只做"读寄存器 + 原样转发" |
| **窗口 + 本任务绑定** | 只有本模块负责的那次 syscall 正在执行、且就是当前任务时才成立 | 让可选守卫（G1/G2/G3）的作用域严格受限 |

> 补充事实：`su` 走的是 execve 魔法路径，**根本不调用 `syscall(45)`**，因此与 `x1<0` 这条判定天然无关。

### 可选守卫 G1/G2/G3（默认全部关闭）

用于覆盖**其它**参数布局（`x2` / `x3` 上的 `memdup_user`、KP 的字符串原语等）。
每个都要求**四道门同时成立**：窗口内 + `apk_win_task == current` + 非受信任 uid + 遍历已被 oracle 证实。

* G1：`memdup_user` —— 源页不可无痕访问时返回**全 0 缓冲**（匿名懒页真实内容就是全 0，与真读该页逐字节等价，但不动页表、不产生缺页）；
* G2：`compat_strncpy_from_user` —— 源页不可无痕访问时返回 0（正是 KP `if (len <= 0) return;` 的"读不到"分支）；
* G3：`compat_copy_to_user` —— 写方向加固（默认关，误伤合法"尚未触碰的接收缓冲"有回归风险）。

**默认全部关闭**的原因有两层：① 真实靶点（`x1<0`）已由 L1 覆盖，不需要它们；
② 关掉后模块**不安装任何全局原语钩子**，系统级足迹只剩 `sys_call_table[45]` 一个槽位。
需要覆盖别的布局时：先 `allow=0,<管理器uid>`，再 `g1=1` / `g2=1`。

### fail-open：宁可不生效，绝不误伤

页表遍历是否可信，用一条**必然成立的事实**来验证：运行中任务的 PC 页**必然 present**。
若遍历把它判成"不可用"，说明标定或参数有误 ⇒ 立刻下线所有依赖遍历的守卫（`walk=0`），
之后任何判定失败都走"原样调用原实现"。合法客户端因此不可能被本模块改变行为。

---

## 三、实现约束（隐蔽性与稳定性）

* 只用架构层自然手段：`MRS` 读系统寄存器、只读页表遍历、`copy_from_kernel_nofault`、框架 hook 原语；
  **无自定义 inline hook、无 creds 篡改、无 dmesg 清除、无 `call_usermodehelper`**。
* **不建 proc / sysfs 节点、不写文件、不开网络**；release 版不产生任何 `printk` 输出
  （日志只在 debug 构建里，由 `APK_DEBUG_LOG` 编译期开关控制）。
* 物理地址掩码按 `shift` 精确限位 `bits[47:12]`（与 LH 驱动一致），Device 属性页（MAIR 高半字节为 0）
  一律拒绝走线性映射读，规避总线违规。
* 卸载完全可逆：先关特性开关 → 排空在途回调 → 摘槽位 → 再排空，避免 `.text` 回收后回调踩空。

---

## 四、部署与接口

```text
构建：  build.ps1                     # 产出 bin/APKey_Hide_<ver>_debug.kpm 与 _release.kpm
上机：  build.ps1 -Deploy -ReleaseOnly   # 构建 + 清设备陈旧副本 + 推唯一文件到 /sdcard/Download
收尾：  build.ps1 -CleanDevice           # ★加载完成之后★ 再执行，清空公共目录里的副本
```

模块身份与产物名由源码宏 `KPM_NAME` / `KPM_VERSION` 自动派生。

运行时接口（`ksud kpm ctl0 APKey_Hide <cmd>`）：

| 命令 | 作用 |
|---|---|
| `status` / `info` | 一行状态：`neg`（L1 命中次数）、`x1n`、`ver`（遍历是否已证实）、`alw`、`walk`、`mair`、各守卫计数 |
| `allow=0` / `allow=0,2000` / `allow=none` | 受信任 uid 白名单 |
| `x1neg=0\|1` | L1 核心短路开关 |
| `g1=0\|1` `g2=0\|1` `g3=0\|1` | 各可选守卫开关（默认 0） |
| `latch=0\|1` | 槽位前置开关（关掉即整模块待机） |
| `recal` | 重新标定（同时把 `ver` 归零，守卫待重新证实） |

---

## 五、兼容性与边界

* 判据依赖「arm64 上 `nr 45 = truncate`」且「`do_sys_truncate` 的长度检查在读路径之前」——
  4.x ~ 6.x 一致，本机 4.19 已确认；换内核需按同样方式复测。
* 本机实测 KP **不挂 32 位 compat 表**（compat nr45 是 `brk`，全组无反应），故本模块只处理原生入口。
* 依赖 KP 导出符号 `current_uid`（以及 hook 框架的 `fp_hook` / `fp_unhook` 等）；
  若某个 KP 变体未导出，模块会**加载失败**而不会带着错误状态运行。
* G1/G2/G3 依赖线性映射标定与 `bits[47:12]` 掩码，且默认关闭；L1 不依赖它们。
* 已知不覆盖：`x2`/`x3` 布局（需显式打开 G1）、写方向口径（G3）、32 位 compat 入口。

---

## 六、文件

| 文件 | 说明 |
|---|---|
| `APKey_Hide.c` | 模块全部实现（单文件，含分区注释） |
| `Makefile` / `build.ps1` | 构建（debug/release）与一键部署 |
