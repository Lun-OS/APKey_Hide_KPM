/*
 * APKey_Hide —— APatch / KernelPatch 鉴权路径「用户参数页被额外换入」侧信道消除
 *
 *   模块名 : APKey_Hide
 *   作  者 : Lun.
 *   许  可 : MIT
 *   平  台 : Android arm64（KernelPatch / APatch / FolkPatch 之上）
 *
 * ---------------------------------------------------------------------------
 * 一、被针对的检测原理 (参考春秋检测文档：https://mingzun09.github.io/Chunqiu-Detector-Problem-solution/#/File/Doc/ksu_kp_sidechannel_zh)
 * ---------------------------------------------------------------------------
 * 检测器准备一块**懒分配页**（mmap 后从不触碰：VMA 有、PTE 无），把它的地址
 * 放到一次 APatch 鉴权请求的某个参数寄存器上，调用后检查该页是否被换入物理
 * 内存（mincore / pagemap 口径）：
 *     0 -> 0  内核没碰它
 *     0 -> 1  内核碰了它 == unexpected read == 判定 KernelPatch/APatch 存在
 *
 * 鉴权请求 = KernelPatch 自建的 syscall：`__NR_supercall = 45`
 * （uapi/scdefs.h；arm64 上 45 恰好是 truncate 的编号，所以 magic 路径叫
 *  /system/bin/truncate）。supercall.c 的 before() 真身：
 *
 *   const char __user *ukey = syscall_argn(args, 0);          // 参数 0 = x0
 *   long cmd = syscall_argn(args, 1) & 0xFFFF;
 *   if (cmd < SUPERCALL_HELLO(0x1000) || cmd > SUPERCALL_MAX(0x1200)) return;
 *   char key[128];
 *   long len = compat_strncpy_from_user(key, ukey, 128);       // ← 读 x0
 *   ...
 *   if (cmd 命中 "su" 快捷串 && is_su_allow_uid(current_uid())) {
 *       args->skip_origin = 1;
 *       args->ret = supercall(0, cmd, x2, x3, x4, x5);         // ← 命令分发
 *   }
 *
 * 而 call_su / call_su_task / call_grant_uid 都是：
 *       struct su_profile *p = memdup_user(arg, sizeof(*p));   // ← 读 x2 / x3
 *
 * 关键：**同一支 x0 指针，原生 truncate 读不读它，完全取决于 x1**（x1 既是
 * truncate 的 length，也是 KP 的 cmd 低 16 位）。原生 do_sys_truncate：
 *
 *     if (length < 0) return -EINVAL;              // ← 在 user_path_at/getname **之前**
 *     error = user_path_at(AT_FDCWD, path, ...);   // ← 只有走到这里才读 path(x0)
 *
 *   调用                                     干净内核(truncate)        KP/APatch
 *   ------------------------------------     ----------------------    --------------------
 *   syscall(45, 懒页,  x1=负)                **一字不读 x0**           读 x0  ★★ 侧信道
 *   syscall(45, 懒页,  x1=正)                读 x0（getname 读路径）   读 x0（同上）→ 无差异
 *   syscall(45, 键串,  x1=0x1010, x2=懒页)   只读 x0                   读 x0 + 读 x2（次要）
 *   syscall(45, 键串,  x1=0x1011, x3=懒页)   只读 x0                   读 x0 + 读 x3（次要）
 *
 * ⇒ 检测器报告的 "Target call: 0->1 unexpected read" 只能是**第一行**：
 *   x1 取负 ⇒ 干净内核一个字节都不读 x0 ⇒ 此时该页上发生的任何读取/换入
 *   （AF 置位、懒页被映射、min_flt 增加）都**只能来自 KP 的 superkey 读取**。
 * ⇒ 第二行（x1 为正）**不是**判据：两边都读 x0，检测器无法据此区分内核，
 *   所以那里必须保持原生语义、一个字都不改（否则会破坏 Read control 对照）。
 * ---------------------------------------------------------------------------
 * 二、对策
 * ---------------------------------------------------------------------------
 * L0【槽位前置】—— 必须最外层
 *     用框架 fp_hook() 直接接管 sys_call_table[__NR_supercall] 槽位（KP 的 hook
 *     链 transit 存成 backup，需要时原样调用 → KP 功能零回归）。
 *     必须在 KP 之前运行：KP 的 supercall 钩子用 fp_hook_wrap 装在链的**槽 0**，
 *     而链的 before 回调按索引 0→N 顺序执行，晚装的挂钩只会落到槽 1（= 在 KP
 *     之后执行，等我们发现时页已经被读了）。所以只有直接接管槽位这一条路。
 *
 * L1【★核心：x1 为负 ⇒ 与干净内核逐字节一致的短路】
 *     x1 < 0 时直接 `return -EINVAL`（不进 KP 链、不碰 origin）：
 *       · 返回值与干净内核**逐字节相同** —— 不引入任何新特征。此前返回 -EFAULT
 *         本身就是一条指纹：干净内核对负 length 给的是 -EINVAL；
 *       · 一个字节都不读 x0：PTE / AF / min_flt / Referenced 全部零变化 ⇒ 0→0；
 *       · **不依赖线性映射标定、不依赖页表遍历**（连 walk 都不需要）⇒ 在任何
 *         内核/KP 变体上都成立，绝不会因标定失败而静默失效
 *         （v0.4~v0.5.2 全部失败的教训就是这个）；
 *       · 零回归：APatch 管理器的 cmd 恒为正数（0x1000..0x1200）永不进本分支；
 *         真实程序 truncate(path, 负长度) 在干净内核上同样是 EINVAL，行为一致。
 *     x1 ≥ 0 时**完全不干预**：原生 getname 本来就读 x0（B 组实测），KP 的读与
 *     我们的读都不增加新信号，故保持原生语义（连 Read control 对照都不受影响）。
 *
 * ★ 管理器安全门（真机 ftrace 实测，`raw_syscalls:sys_enter` filter id==45）：
 *   APatch 管理器的 supercall 来自 **uid 10266（app 自身，不是 root）**，形如
 *       NR 45 (x0=b400007232224080, x1=0xD0811581_XXXX, x2=..., x3=..., x5=0x73)
 *   即 x1 = 正数 + 高 32 位非签名（cmd 在低 16 位），KP 侧 is_tm=1 免密钥通过。
 *   ⇒ 窗口只对 `(x1>>32)==0 且 非受信任 uid` 打开；G1/G2/G3 默认关闭
 *     ⇒ 管理器路径上本模块只做"读寄存器 + 原样转发"，**零干预**。
 *   ⇒ su 实测**根本不调用 nr45**（走 execve 魔法路径），与本模块天然无关。
 *
 * G1【窗口内 memdup_user 守卫】—— 次要路径（x2/x3，需 su 白名单 uid）
 *     内核符号全局共用，不能无条件改写行为；因此只在「窗口内 + 调用者是当前
 *     任务 + 源页确实不可用」时才偏离：源页不可用 → 返回一块**全 0 缓冲**。
 *     这不是编造：匿名懒页的真实内容就是全 0，`memdup_user` 真去读它也只得到
 *     全 0，两者在 KP 侧**逐字节等价**（call_su 拿到 to_uid=0、scontext="" 的
 *     profile，行为与原来一致），而进程页表一个字节都没动、一次缺页都没发生。
 *     源页可用 → 原样调用原实现，合法客户端（apk 管理器）路径 100% 不变。
 *
 * G2【compat_strncpy_from_user 守卫】
 *     KP 自己的字符串读取原语（x0 密钥串、argv[1]、KLOG 等）。源页不可用时
 *     返回 0 —— 对 KP 而言 `if (len <= 0) return;` 就是"读不到"的正常分支，
 *     语义自洽，且不碰该页。
 *
 * G3【compat_copy_to_user 守卫】（默认关闭，写方向加固）
 *     若某个命令往懒分配页**写**（SU_GET_PATH / SU_LIST / BUILD_TIME 等），
 *     写缺页同样会把页换入。默认关闭是因为合法客户端可能传入刚 mmap 未触碰
 *     的接收缓冲，跳过拷贝有回归风险；需要时用 `g3=1` 打开。
 *
 * L4【时延均衡】
 *     cmd 越界时 KP 立即返回，cmd 在范围内要读密钥并校验，实测比值可达 2.10
 *     （≥2 就会被"鉴权时延探测"判定存在 KP；复测 1.25，抖动大）。本模块在越界
 *     分支上做等量的一次 128B 密钥读取，把两条路径拉平。读的对象就是 x0 ——
 *     原生 truncate 本来也要读它，不产生任何新增信号。
 *
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <common.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <hook.h>
#include <syscall.h>
#include <kallsyms.h>
#include <pgtable.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("APKey_Hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("MIT");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("suppress KernelPatch supercall param-page reads;https://github.com/Lun-OS/APKey_Hide_KPM");

/* ========================== 常量 ========================== */
#define APK_NR_SUPERCALL    45           /* __NR_supercall（arm64 上与 truncate 同号） */
#define APK_CMD_MIN         0x1000       /* SUPERCALL_HELLO */
#define APK_CMD_MAX         0x1200       /* SUPERCALL_MAX   */
#define APK_MD_MAX          4096         /* 超过该长度的 memdup_user 不干预（不可能是 su_profile） */
#define APK_EQ_LEN          128          /* 时延均衡读取长度 = KP 的 MAX_KEY_LEN */
#define APK_ID_BYTES        64           /* 标定内容比对长度（内核 _stext 前 64B） */
#define APK_PHYS_MAX        0x4000000000ULL     /* 物理地址上限 256GB（防脏描述符构造巨 VA） */
#define APK_PHYS_MASK_MAX   0x0000FFFFFFFFF000ULL /* bits[47:12] */
#define APK_DRAIN_LOOPS     400000000UL  /* 卸载排空上限（窗口为微秒级） */

/* GFP_KERNEL 位值：__GFP_DIRECT_RECLAIM|__GFP_KSWAPD_RECLAIM|__GFP_IO|__GFP_FS
 * = (0x400|0x800)|0x40|0x80 = 0xCC0（框架 gfp.h 只有注释版定义，故就地展开） */
#define APK_GFP_KERNEL      0xCC0u

/* 长度不超过 key 的取小 */
#define APK_MIN(a, b)       ((a) < (b) ? (a) : (b))

/* ========================== 日志（release 零 dmesg 痕迹） ========================== */
static int (*apk_printk)(const char *fmt, ...);

#ifdef APK_DEBUG_LOG
#define APK_LOG(fmt, ...)                                                        \
    do {                                                                         \
        if (apk_printk)                                                          \
            apk_printk("[APKey_Hide] " fmt, ##__VA_ARGS__);                      \
    } while (0)
#else
#define APK_LOG(fmt, ...) do { } while (0)
#endif

/* ========================== 无 libc 基础工具 ========================== */
static void apk_memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
}

static void apk_bzero(void *dst, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = 0;
}

static int apk_str_eq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a == (unsigned char)*b;
}

static int apk_str_prefix(const char *s, const char *p)
{
    while (*p) {
        if (*s++ != *p++)
            return 0;
    }
    return 1;
}

/* 十六进制数值解析（排障用：walk=<hex> 手动指定线性偏移） */
static uint64_t apk_hex2u64(const char *s)
{
    uint64_t v = 0;
    int i = 0;

    if (!s)
        return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
    for (; s[i] && i < 18; i++) {
        char c = s[i];
        uint64_t d;
        if (c >= '0' && c <= '9')
            d = (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (uint64_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            d = (uint64_t)(c - 'A' + 10);
        else
            break;
        v = (v << 4) | d;
    }
    return v;
}

static void apk_hex64(char *out, uint64_t v)
{
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 15; i >= 0; i--)
        out[i] = h[(int)((v >> (i * 4)) & 0xF)];
    out[16] = '\0';
}

/* ========================== 架构寄存器读取 ========================== */
static inline uint64_t apk_mrs_ttbr0(void)
{
    uint64_t v;
    asm volatile("mrs %0, ttbr0_el1" : "=r"(v));
    return v;
}

static inline uint64_t apk_mrs_ttbr1(void)
{
    uint64_t v;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(v));
    return v;
}

static inline uint64_t apk_mrs_tcr(void)
{
    uint64_t v;
    asm volatile("mrs %0, tcr_el1" : "=r"(v));
    return v;
}

static inline uint64_t apk_mrs_mair(void)
{
    uint64_t v;
    asm volatile("mrs %0, mair_el1" : "=r"(v));
    return v;
}

/* ========================== 可调参数 / 开关 ========================== */
/* ★v0.5.5：G1/G2 默认**关闭**。
 * 理由（真机实测）：APatch 管理器的 supercall（uid 10266）cmd 落在范围内 ⇒ 会落在
 * G1/G2 的窗口里，而它是**非 root 的可信管理器**，任何"替它做读取"的行为都会
 * 打断它的鉴权链。而真实检测器的靶点（x1<0）已由 L1 单独覆盖，不再需要 G1/G2。
 * 需要覆盖 x2/x3 布局时：ctl0 `allow=0,<管理器uid>` 之后 `g1=1` / `g2=1`。 */
static int apk_g1_on = 0;        /* memdup_user 守卫（默认关） */
static int apk_g2_on = 0;        /* compat_strncpy_from_user 守卫（默认关） */
static int apk_g3_on = 0;        /* compat_copy_to_user 守卫（默认关，写方向加固） */
/* ★v1.0.0：L4 时延均衡默认**关闭**（按实测数据定）。
 * 真机测量（probe/apk_timing，iters=20000，x0=present/懒页，见 README §0.3）：
 *      uid=10254（检测器同身份）  in/out = 0.993 / 0.998
 *      uid=2000（KP su 白名单）   in/out = 1.015
 *      uid=0                      in/out ≈ 1.00
 *      噪声基准（同一调用测两遍） = 0.999   ← 说明测量分辨力足够，>2 一定会被看出来
 * 即本机 KP（FolkPatch：密钥读取先于 cmd 门控）对"范围内/范围外"两条分支的开销
 * 几乎相同 ⇒ **时序口径本机不成立，无需补偿**；此时再补读一次只会把 x1≥0 分支
 * 压慢（比值往下偏），属于无收益的动作 ⇒ 默认关闭。
 * 只有在上游式 KP（cmd 门控 **先于** 密钥读取，范围外分支明显更快）上才有必要打开：
 *     ctl0 `eq=1`。打开后本分支 x1≥0、原生 getname 也读 x0 ⇒ 不产生新信号。 */
static int apk_eq_on = 0;        /* 时延均衡（默认关；实测本机不需要） */
static int apk_latch_on = 1;     /* 槽位前置（关掉即整模块待机） */
static int apk_x1neg_on = 1;     /* ★L1：x1<0 时同值短路（核心；不依赖标定） */

/* ================== 受信任调用者白名单 ==================
 * 判定只用 KernelPatch 导出的 current_uid()（kputils.h；KP 内部已用运行时探测的
 * task_struct→cred→uid 偏移实现，模块侧**不需要**任何硬编码偏移或启发式探测）。
 * 默认白名单 = {0}（仅 root）；ctl0 `allow=0,2000` 可放宽，`allow=none` 清空。
 * ============================================================================ */
#define APK_ALLOW_MAX 8
static uint32_t apk_allow[APK_ALLOW_MAX] = {0};
static int      apk_allow_n = 1;

static int apk_uid_trusted(void)
{
    uint32_t u = (uint32_t)current_uid();
    int i;

    for (i = 0; i < apk_allow_n; i++)
        if (apk_allow[i] == u)
            return 1;
    return 0;
}

/* ========================== 全局状态 ========================== */
static uintptr_t *apk_sct;                 /* sys_call_table */
static uintptr_t  apk_saved45;             /* 被接管前槽位值（KP 链 transit / 原生 truncate） */
static int        apk_latch_installed;

static void *(*apk_orig_memdup_user)(const void __user *src, size_t len);
static long  (*apk_orig_scfu)(char *dest, const char __user *src, long count);
static int   (*apk_orig_c2u)(void __user *to, const void *from, int n);
static void *(*apk_kmalloc)(size_t size, unsigned int flags);
static void  (*apk_kfree)(const void *p);
static long  (*apk_nofault_r)(void *dst, const void *src, size_t n);
static int   (*apk_snprintf)(char *buf, size_t sz, const char *fmt, ...);
static long  (*apk_copy_to_user)(void *to, const void *from, unsigned long n);

/* 页表研判状态 */
static int      apk_walk_ok;               /* 1 = 用户页表研判已标定可用 */
static int      apk_st_done;               /* 自标定是否已尝试 */
/* ★v0.5.4：线性映射遍历是否已被"必然 present 的页"（运行中任务的 PC 页）证实。
 * 只有它为 1，G1/G2/G3 这些靠遍历判断"源页是否可用"的守卫才允许上线 ——
 * 否则"标定成功但遍历其实不可用"会让守卫拿错误的判定去吃掉合法读取
 * （v0.5.3 管理器/su 失联的根因）。 */
static int      apk_walk_ver;
static uint64_t apk_lin_off;               /* 线性映射偏移 */
static uint64_t apk_upgd;                  /* 当前进程 user PGD 的内核线性别名 VA */
static uint64_t apk_mair;   /* ★必须是 64 位：MAIR_EL1 的 AttrIndx 4..7 位于 bits[39:32]，
                             * 截成 uint32 会让 index4(MT_NORMAL=0xFF) 读成 0，
                             * 使每个用户页都被误判为 Device（v0.5.2 walk=0 的根因）。 */
static int      apk_ubits;                 /* 用户 VA 位宽 39/48 */
static int      apk_ups;                   /* 用户页大小 log2 */
static int      apk_ulevel;                /* 用户页表级数 */

/* 受保护窗口 */
static volatile int apk_win_cnt;
static struct task_struct *apk_win_task;

/* 计数器（ctl0 用它判断"到底有没有命中目标路径"） */
static volatile uint32_t apk_n_win;        /* 进入窗口次数 */
static volatile uint32_t apk_n_blk;        /* L2 命中：x0 不可读 → 整条链短路（次要路径） */
static volatile uint32_t apk_n_neg;        /* ★L1 命中：x1<0 → 原生不读 x0，直接同值返回（关键指标） */
static volatile uint32_t apk_n_g1;         /* G1 命中：懒页被替换为全 0 缓冲 */
static volatile uint32_t apk_n_g1_o;       /* G1 放行（源页可用 / 窗口外） */
static volatile uint32_t apk_n_g2;         /* G2 命中：懒页字符串读取被短路 */
static volatile uint32_t apk_n_g3;         /* G3 命中（写方向） */
static volatile uint32_t apk_n_eq;         /* 时延均衡次数 */
static volatile uint32_t apk_n_absent;     /* 页表研判判定"不可用"次数 */

/* KernelPatch 导出符号（由 KPM 加载器解析） */
extern long compat_strncpy_from_user(char *dest, const char __user *src, long count);
extern int  has_syscall_wrapper;
/* compat_copy_to_user 的声明由 <kputils.h> 提供：
 * int __must_check compat_copy_to_user(void __user *to, const void *from, int n); */

/* ==========================================================================
 * 一、用户页表研判
 * ========================================================================== */

static inline uint64_t apk_phys_mask(int shift)
{
    return (~((1ULL << shift) - 1)) & APK_PHYS_MASK_MAX;
}

/* 解析 va 的叶子描述符。
 *   pgd_va : 顶层页表的内核线性别名 VA
 *   ps/level: 该地址空间的页大小 log2 与页表级数
 *   lin_off: 本次遍历使用的线性映射偏移（标定期为候选值）
 * 返回 0 成功；-1 未映射/描述符非法；-2 叶子为 Device 属性；-3 基础设施不可用 */
static int apk_walk(uint64_t pgd_va, uint64_t va, int ps, int level, int require_user,
                    uint64_t lin_off, uint64_t *out_pa, uint64_t *out_leaf_va,
                    uint64_t *out_leaf, int *out_blk)
{
    uint64_t base = pgd_va;
    uint64_t ent = 0;
    int lv, idx, shift;

    if (!apk_nofault_r || !pgd_va)
        return -3;
    if (level < 2 || level > 4)
        return -3;

    for (lv = level; lv > 1; lv--) {
        shift = ps + 9 * (lv - 1);
        idx = (int)((va >> shift) & 0x1FF);

        if (apk_nofault_r(&ent, (void *)(base + (uint64_t)idx * 8), 8) != 0)
            return -1;
        if (!(ent & 0x1))
            return -1;                       /* 无效描述符 */

        if ((ent & 0x3) == 0x1) {            /* 块映射（大页）即叶子 */
            *out_pa = (ent & apk_phys_mask(shift)) | (va & ((1ULL << shift) - 1));
            *out_leaf_va = base + (uint64_t)idx * 8;
            *out_leaf = ent;
            *out_blk = shift;
            goto leaf_check;
        }

        {                                    /* 表映射：下钻 */
            uint64_t next_pa = ent & apk_phys_mask(ps);
            if (next_pa == 0 || next_pa >= APK_PHYS_MAX)
                return -1;                   /* 防脏描述符构造巨 VA */
            base = next_pa + lin_off;
        }
    }

    idx = (int)((va >> ps) & 0x1FF);         /* PTE 级 */
    if (apk_nofault_r(&ent, (void *)(base + (uint64_t)idx * 8), 8) != 0)
        return -1;
    if ((ent & 0x3) != 0x3)
        return -1;                           /* PTE 级必须为页描述符 */
    *out_pa = (ent & apk_phys_mask(ps)) | (va & ((1ULL << ps) - 1));
    *out_leaf_va = base + (uint64_t)idx * 8;
    *out_leaf = ent;
    *out_blk = ps;

leaf_check:
    if (require_user && !(ent & PTE_USER))
        return -1;                           /* 非用户映射 → 不算"该页可用" */
    /* Device 属性判定：必须用真实 MAIR_EL1。若 MAIR 还没取到（apk_mair==0），
     * 就**跳过**该判定 —— 否则 (0>>..)&0xFF==0 会把每个叶子都误判成 Device，
     * 导致页表遍历整体失效（v0.5.0 的 walk=0 bug 就是这么来的）。 */
    if (apk_mair) {
        uint8_t attr = (uint8_t)((apk_mair >> (((ent >> 2) & 7) * 8)) & 0xFF);
        if ((attr & 0xF0) == 0)
            return -2;                       /* Device 内存：拒绝线性映射读（DEVAPC 防护） */
    }
    return 0;
}

/* 刷新当前进程 user PGD 的线性别名 VA（进程切换后 TTBR0 变化）
 * 只清 ASID([63:48]) 与 4KB 以下低位（CnP/保留位），保留 BADDR 全部有效位 */
static void apk_refresh_upgd(void)
{
    uint64_t t = apk_mrs_ttbr0() & ((1ULL << 48) - 1) & ~0xFFFULL;
    apk_upgd = t ? (t + apk_lin_off) : 0;
}

/* va 所在用户页是否已换入（present 且为用户映射）*/
static int apk_page_present(uint64_t va)
{
    uint64_t pa = 0, leaf_va = 0, leaf = 0;
    int blk = 0;

    if (!apk_upgd || !va)
        return 0;
    return apk_walk(apk_upgd, va, apk_ups, apk_ulevel, 1, apk_lin_off,
                    &pa, &leaf_va, &leaf, &blk) == 0;
}

/* va 所在用户页是否"不可用"（不可无痕访问）。
 * 返回 1 仅当**确信**该页没有有效用户 PTE —— 这是 G1/G2 唯一的放行判据，
 * 任何不确定（未标定 / TTBR0 不可用）都必须返回 0（fail-open）。 */
static int apk_user_page_absent(uint64_t va)
{
    if (!apk_walk_ok)
        return 0;
    if (va < 0x1000)
        return 1;                                   /* NULL / 超低位：不可能是合法参数 */
    if (va >= (1ULL << apk_ubits))
        return 1;                                   /* 超出用户 VA 位宽：内核地址/非法 */
    apk_refresh_upgd();
    if (!apk_upgd)
        return 0;                                   /* TTBR0 不可用 → 不判定 */
    if (apk_page_present(va))
        return 0;
    apk_n_absent++;
    return 1;
}

/* 线性映射偏移候选：(PAGE_OFFSET 的 4 种历史取值) × (是否再减 memstart_addr)。
 * arm64 的线性映射是 va = pa - memstart_addr + PAGE_OFFSET，故 offset = PO - memstart。
 * 不硬编码任何具体机器的值：全部候选靠"内容比对"择优。 */
static int apk_po_candidates(uint64_t *out, int max)
{
    /* arm64 的 PAGE_OFFSET 有确定公式（v4.6+ 起）：
     *     VA_START    = ~((1 << VA_BITS) - 1) + 1        // modules/vmalloc 起点
     *     PAGE_OFFSET = ~((1 << (VA_BITS - 1)) - 1)      // linear map 起点
     * 内核侧 VA_BITS 直接由 TCR_EL1.T1SZ 得到（VA_BITS = 64 - T1SZ）。
     * ⇒ 39 位内核算出 0xffffffc000000000，48 位内核算出 0xffff800000000000，
     *   与真机布局一致（sys_call_table 落在 0xffffff80..0xffffffbf 的镜像区，
     *   正说明 linear 基址在 0xffffffc000000000）。
     * 线性映射 va = pa - memstart_addr + PAGE_OFFSET ⇒ 偏移 = PAGE_OFFSET - memstart。
     * 仍给出两种位宽 × 是否减 memstart 的组合，最终由内容逐字节比对择优。 */
    uint64_t memstart = 0;
    uint64_t ms = (uint64_t)(uintptr_t)kallsyms_lookup_name("memstart_addr");
    int vb_k = 64 - (int)((apk_mrs_tcr() >> 16) & 0x3F);   /* 内核 VA_BITS */
    int vb_alt = (vb_k == 39) ? 48 : 39;
    int n = 0, k, i;

    if (ms)
        (void)apk_nofault_r(&memstart, (void *)ms, 8);

    for (k = 0; k < 4; k++) {
        int vb = (k & 1) ? vb_alt : vb_k;
        uint64_t po;
        int dup;

        if (vb < 32 || vb > 52)
            continue;
        /* k<2: PAGE_OFFSET = ~((1<<(VA_BITS-1))-1)
         * k>=2: VA_START   = ~((1<<VA_BITS)-1)+1（兜底：万一公式/位宽判断有误） */
        po = (k < 2) ? ~((1ULL << (vb - 1)) - 1) : ~((1ULL << vb) - 1) + 1;
        dup = 0;
        for (i = 0; i < n; i++)
            if (out[i] == po)
                dup = 1;
        if (!dup && n < max)
            out[n++] = po;
        if (memstart) {
            dup = 0;
            for (i = 0; i < n; i++)
                if (out[i] == po - memstart)
                    dup = 1;
            if (!dup && n < max)
                out[n++] = po - memstart;
        }
    }
    return n;
}

/* 从 TCR_EL1 推导用户侧 VA 位宽 / 页大小 / 页表级数（确定性，无需比对） */
static void apk_user_params_from_tcr(void)
{
    uint64_t tcr = apk_mrs_tcr();
    int tg0 = (int)((tcr >> 14) & 0x3);

    apk_ubits = 64 - (int)(tcr & 0x3F);
    if (apk_ubits != 39 && apk_ubits != 48)
        apk_ubits = 48;
    apk_ups = (tg0 == 1) ? 16 : ((tg0 == 2) ? 14 : 12);
    apk_ulevel = (apk_ubits - 4) / (apk_ups - 3);
    if (apk_ulevel < 2 || apk_ulevel > 4) {
        apk_ubits = 39;
        apk_ups = 12;
        apk_ulevel = 3;
    }
}

/* ---- 主标定：内核侧内容比对（读的全是内核内存，对用户进程零副作用） ----
 * 用 TTBR1_EL1 的 BADDR(= phys(swapper_pg_dir)) 配合候选偏移解析 _stext，
 * 再比对「解析出的物理页经线性别名读到的前 64 字节」与「_stext 自身映射的内容」。
 * 逐字节相同 ⇒ 偏移正确（KASLR 与厂商 EL2 干扰都被内容自洽吸收）。 */
static int apk_verify_offset(uint64_t d, uint64_t kpgd, uint64_t stext_va, int kbits, int kps)
{
    uint64_t pa = 0, leaf_va = 0, leaf = 0;
    uint64_t page_mask = (1ULL << kps) - 1;
    int level = (kbits - 4) / (kps - 3);
    int blk = 0, i;

    if (!kpgd || level < 2 || level > 4)
        return 0;
    if (apk_walk(kpgd, stext_va, kps, level, 0, d, &pa, &leaf_va, &leaf, &blk) != 0)
        return 0;
    if (pa == 0 || (pa & page_mask) != (stext_va & page_mask))
        return 0;                            /* 页内偏移必须自洽 */

    for (i = 0; i < APK_ID_BYTES; i++) {
        unsigned char x = 0, y = 0;
        if (apk_nofault_r(&x, (void *)(stext_va + (uint64_t)i), 1) != 0)
            return 0;
        if (apk_nofault_r(&y, (void *)((pa & ~page_mask) + d + (uint64_t)i), 1) != 0)
            return 0;
        if (x != y)
            return 0;
    }
    return 1;
}

/* ---- 主标定（路径 A）：用 kimage_voffset 直接得到 (_text VA, PA) 对，绕过页表遍历 ----
 * 内核变量 kimage_voffset = _text_va - _text_pa，是 arm64 启动时写好的；读到它
 * 就等于同时拿到了 _text 的 **物理地址**。于是只需要扫描线性偏移候选，比对
 *   [ _text_pa + d , +64 )  与  [ _text_va , +64 )
 * 的字节是否相同 —— 相同即锁定线性映射偏移。全程只读内核内存，零副作用，
 * 且完全不依赖页表遍历（遍历那套留作交叉校验/兜底）。 */
static int apk_calib_kimage(void)
{
    unsigned char ref[APK_ID_BYTES];
    uint64_t kimg_sym = (uint64_t)(uintptr_t)kallsyms_lookup_name("kimage_voffset");
    uint64_t text_va = (uint64_t)(uintptr_t)kallsyms_lookup_name("_text");
    uint64_t kv = 0, text_pa;
    uint64_t cands[16];
    int n, i, k;

    if (!text_va)
        text_va = (uint64_t)(uintptr_t)kallsyms_lookup_name("_stext");
    if (!kimg_sym || !text_va) {
        APK_LOG("kimg: sym missing kv=%llx text=%llx\n",
                (unsigned long long)kimg_sym, (unsigned long long)text_va);
        return 0;
    }
    if (apk_nofault_r(&kv, (void *)kimg_sym, 8) != 0 || !kv) {
        APK_LOG("kimg: read kimage_voffset failed\n");
        return 0;
    }
    text_pa = text_va - kv;
    if (text_pa < 0x1000 || text_pa >= APK_PHYS_MAX) {
        APK_LOG("kimg: text_va=%llx kv=%llx -> text_pa=%llx(越界)\n",
                (unsigned long long)text_va, (unsigned long long)kv,
                (unsigned long long)text_pa);
        return 0;
    }

    for (i = 0; i < APK_ID_BYTES; i++)
        if (apk_nofault_r(&ref[i], (void *)(text_va + (uint64_t)i), 1) != 0)
            return 0;                        /* 参照内容读不到 → 放弃 */

    n = apk_po_candidates(cands, 16);
    for (i = 0; i < n; i++) {
        int ok = 1;
        for (k = 0; k < APK_ID_BYTES; k++) {
            unsigned char b = 0;
            if (apk_nofault_r(&b, (void *)(text_pa + cands[i] + (uint64_t)k), 1) != 0) {
                ok = 0;
                break;
            }
            if (b != ref[k]) {
                ok = 0;
                break;
            }
        }
        APK_LOG("kimg: text_pa=%llx d=%llx -> %s\n", (unsigned long long)text_pa,
                (unsigned long long)cands[i], ok ? "MATCH" : "no");
        if (ok) {
            apk_lin_off = cands[i];
            return 1;
        }
    }
    APK_LOG("kimg: no candidate matched\n");
    return 0;
}

static int apk_calib_kernel(void)
{
    uint64_t tcr = apk_mrs_tcr();
    uint64_t stext_va;
    uint64_t baddr1;
    uint64_t cands[16];
    int n, i, x, y, done = 0;

    /* ★ MAIR_EL1 必须在任何 apk_walk() 之前取到：apk_walk() 的叶子检查要用它判
     *   Device 属性；apk_mair==0 会让所有叶子被误判为 Device（v0.5.0 walk=0 的根因）。 */
    apk_mair = apk_mrs_mair();

    if (!apk_nofault_r) {
        APK_LOG("cal: nofault_r NULL\n");
        return 0;
    }

    stext_va = (uint64_t)(uintptr_t)kallsyms_lookup_name("_stext");
    baddr1 = apk_mrs_ttbr1() & ((1ULL << 48) - 1) & ~0xFFFULL;
    if (!stext_va || !baddr1) {
        APK_LOG("cal: stext=%llx ttbr1=%llx\n", (unsigned long long)stext_va,
                (unsigned long long)baddr1);
        return 0;
    }

    n = apk_po_candidates(cands, 16);
    if (!n) {
        APK_LOG("cal: no candidates\n");
        return 0;
    }

    APK_LOG("cal: ttbr1=%llx stext=%llx cands=%d\n",
            (unsigned long long)baddr1, (unsigned long long)stext_va, n);

    /* ★独立判据：swapper_pg_dir 的物理地址 + 正确的线性偏移 = 它的线性别名，
     *   **一定落在已映射区**（probe_kernel_read 能读）；偏移错误的候选则指向
     *   未映射的 kernel VA，读取直接 -EFAULT。用这个先把候选筛一遍并留痕。 */
    {
        int nn = 0;
        uint64_t keep[16];
        for (i = 0; i < n; i++) {
            uint64_t ent0 = 0;
            long rc = apk_nofault_r(&ent0, (void *)(baddr1 + cands[i]), 8);
            APK_LOG("cal cand[%d] d=%llx rc=%ld ent0=%llx\n", i,
                    (unsigned long long)cands[i], rc, (unsigned long long)ent0);
            if (rc == 0)
                keep[nn++] = cands[i];
        }
        if (nn) {
            for (i = 0; i < nn; i++)
                cands[i] = keep[i];
            n = nn;
        }
    }

    {
        int tg1 = (int)((tcr >> 30) & 0x3);
        /* TG1 编码与 TG0 **不同**：0b01=16KB, 0b10=4KB, 0b11=64KB（曾经写反过） */
        int tg1_ps = (tg1 == 1) ? 14 : ((tg1 == 2) ? 12 : 16);
        int bits_tcr = 64 - (int)((tcr >> 16) & 0x3F);
        static const int bits_c[2] = {39, 48};
        static const int ps_c[3] = {12, 16, 14};
        int bits_try[3], ps_try[4], nb = 0, np = 0;

        bits_try[nb++] = (bits_tcr == 39 || bits_tcr == 48) ? bits_tcr : 39;
        for (x = 0; x < 2; x++)
            if (bits_c[x] != bits_try[0])
                bits_try[nb++] = bits_c[x];
        ps_try[np++] = tg1_ps;
        for (y = 0; y < 3; y++)
            if (ps_c[y] != tg1_ps)
                ps_try[np++] = ps_c[y];

        for (i = 0; i < n && !done; i++) {
            for (x = 0; x < nb && !done; x++) {
                for (y = 0; y < np && !done; y++) {
                    if (!apk_verify_offset(cands[i], baddr1 + cands[i], stext_va,
                                           bits_try[x], ps_try[y]))
                        continue;
                    apk_lin_off = cands[i];
                    done = 1;
                }
            }
        }
        APK_LOG("cal: cands=%d tcr=%llx tg1_ps=%d bits=%d -> %s lin=%llx\n",
                n, (unsigned long long)tcr, tg1_ps, bits_tcr,
                done ? "OK" : "FAILED", (unsigned long long)apk_lin_off);
    }

    return done;
}

/* ---- 兜底标定：用户侧内容比对（仅在内核侧标定失败时尝试） ----
 * 锚点 = 本次 syscall 的用户 PC 所在页：它**必然已换入**（马上要从它继续执行），
 * 所以这里的 memdup_user 参照读不会引发缺页；若该页是 --x（不可读）而返回
 * EFAULT，则本函数直接放弃（fail-open），绝不因此制造缺页。 */
static int apk_calib_user(uint64_t pc)
{
    unsigned char ref[APK_ID_BYTES];
    uint64_t ttbr0 = apk_mrs_ttbr0() & ((1ULL << 48) - 1) & ~0xFFFULL;
    uint64_t cands[8];
    void *p;
    int n, i, done = 0;

    if (!apk_nofault_r || !apk_orig_memdup_user || !ttbr0 || !pc)
        return 0;

    pc &= ~0xFFFULL;
    p = apk_orig_memdup_user((const void __user *)pc, APK_ID_BYTES);
    if (!p || IS_ERR(p))
        return 0;                            /* --x / 不可读 → 放弃 */
    apk_memcpy(ref, p, APK_ID_BYTES);
    if (apk_kfree)
        apk_kfree(p);

    apk_mair = apk_mrs_mair();
    apk_user_params_from_tcr();
    n = apk_po_candidates(cands, 8);

    for (i = 0; i < n && !done; i++) {
        uint64_t pa = 0, leaf_va = 0, leaf = 0, base;
        uint64_t pmask = (1ULL << apk_ups) - 1;
        int blk = 0, ok = 1, k;

        if (apk_walk(ttbr0 + cands[i], pc, apk_ups, apk_ulevel, 1, cands[i],
                     &pa, &leaf_va, &leaf, &blk) != 0)
            continue;
        base = (pa & ~pmask) + cands[i];
        for (k = 0; k < APK_ID_BYTES; k++) {
            unsigned char b = 0;
            if (apk_nofault_r(&b, (void *)(base + (uint64_t)k), 1) != 0) {
                ok = 0;
                break;
            }
            if (b != ref[k]) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            apk_lin_off = cands[i];
            done = 1;
        }
    }
    return done;
}

/* 遍历正确性 oracle：任务正在运行 ⇒ 它的用户 PC 所在页**必然 present**。
 * 若我们的遍历说它"不可用"，只能是标定/参数错了 ⇒ 永久 fail-open，
 * 绝不拿错误的"不可用"去拦合法客户端的请求。 */
static void apk_walk_sanity(uint64_t pc)
{
    apk_refresh_upgd();
    if (!apk_upgd) {
        apk_walk_ok = 0;
        APK_LOG("oracle: upgd=0 -> walk off\n");
        return;
    }
    if (!apk_page_present(pc & ~0xFFFULL)) {
        apk_walk_ok = 0;
        APK_LOG("oracle: pc=%llx NOT present -> walk off (fail-open)\n",
                (unsigned long long)pc);
        return;
    }
    apk_walk_ver = 1;                    /* 遍历已被必然 present 的页证实 */
    APK_LOG("oracle: pc=%llx present -> walk armed (ver=1)\n", (unsigned long long)pc);
}

/* ==========================================================================
 * 二、受保护窗口 + 槽位前置
 * ========================================================================== */

#define APK_SAVED_CALL(regs, a0, a1, a2, a3, a4, a5)                              \
    (has_syscall_wrapper                                                          \
         ? ((long (*)(struct pt_regs *))(apk_saved45))(regs)                      \
         : ((long (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,            \
                      uint64_t))(apk_saved45))(a0, a1, a2, a3, a4, a5))

static long apk_sc45_entry(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                           uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    struct pt_regs *regs = 0;
    uint64_t x0, x1, cmd;
    long ret;

    (void)a6;
    (void)a7;

    if (!apk_saved45)
        return -ENOSYS;

    if (has_syscall_wrapper) {
        regs = (struct pt_regs *)a0;
        x0 = regs->regs[0];
        x1 = regs->regs[1];
    } else {
        x0 = a0;
        x1 = a1;
    }
    cmd = x1 & 0xFFFF;

    /* ---- 1) ★L1 核心：x1 为负 ⇒ 与干净内核逐字节一致的短路（不读 x0、不依赖标定） ----
     *
     *  真机实测（probe/apk_tgt，本机 KP = FolkPatch diag 版，uid 2000）：
     *    [A] syscall(45, x0=lazy,     x1=-1)      → 返回 EINVAL(22)，**懒页 resident 0→1**
     *    [A] syscall(45, x0=unmapped, x1=-1)      → 返回 EINVAL(22)
     *    [B] syscall(45, x0=PROT_NONE,x1=0x1010)  → 返回 EFAULT(14)
     *    [B] syscall(45, x0=lazy,     x1=0x1010)  → 懒页同样被换入
     *  A 组第三个用例的 -EINVAL 是决定性的：同一支坏指针在 A(−1) 返回 EINVAL、在 B(+0x1010)
     *  返回 EFAULT ⇒ 证明原生 do_sys_truncate 的
     *      [if (length < 0) return -EINVAL;]   在 user_path_at()/getname() **之前**，
     *  即**干净内核在 x1<0 时一个字节都不读 x0**。
     *
     *  ⇒ 侧信道只存在于 x1<0 这一种参数布局：此时 x0 上发生的任何读取/换入
     *    （AF 置位、懒分配页被映射、min_flt 增加）都**只可能来自 KP 的 superkey 读取**
     *    —— 这正是检测器 "Target call 0→1 unexpected read" 的全部来源。
     *  ⇒ 反之，x1≥0 时原生 getname 本来就会读 x0（B 组实测），KP 的读与我们的读
     *    都不增加任何新信号，所以那里**完全不干预**（零回归）。
     *
     *  对策：x1<0 ⇒ 直接返回 -EINVAL：
     *      · 与干净内核返回值逐字节相同，不引入任何新的可观测特征（此前返回 -EFAULT
     *        本身就是一条指纹：干净内核给的是 -EINVAL）；
     *      · 一个字节都不读 x0：PTE / AF / min_flt / Referenced 全部零变化；
     *      · **不依赖线性映射标定、不依赖页表遍历**（连 walk 都不需要）⇒ 在任何
     *        内核与 KP 变体上都成立，绝不会因标定失败而静默失效（v0.4~v0.5.2 的教训）。
     *  APatch 管理器的 cmd 恒为正数（0x1000~0x1200），永不进入本分支。 */
    if (apk_x1neg_on && (long)x1 < 0 && !apk_uid_trusted()) {
        if (apk_n_neg < 8)                   /* 前 8 次留痕，便于真机核对（debug 版） */
            APK_LOG("L1 x1<0 -> EINVAL #%u x0=%llx x1=%llx\n",
                    (unsigned)apk_n_neg, (unsigned long long)x0,
                    (unsigned long long)x1);
        apk_n_neg++;
        return -EINVAL;
    }

    /* ---- 2) 首次进入（只有 x1≥0 才会走到）：标定兜底 + 遍历 oracle ----
     *   仅用于 G1/G2 的"源页是否可用"研判，失败即永久 fail-open（宁可不生效，
     *   绝不误拦合法客户端）；L1 核心短路不依赖这一步。 */
    if (!apk_st_done) {
        apk_st_done = 1;
        if (!apk_walk_ok && regs)
            apk_walk_ok = apk_calib_user(regs->pc);
        if (apk_walk_ok && regs)
            apk_walk_sanity(regs->pc);
    }

    /* ---- 3) cmd 越界（x1≥0）：KP 与 origin 都会读 x0 → 原样放行 ----
     * 顺带做等量读取，拉平"范围内/范围外"时延（阈值 >2 的鉴权时延探测）。 */
    if (cmd < APK_CMD_MIN || cmd > APK_CMD_MAX) {
        /* ★v1.0.0 修复：这里原先用 apk_orig_scfu（G2 hook 的 trampoline），
         * 而 G1/G2 默认关闭后该指针恒为 0 ⇒ 时延均衡静默失效。改为**直接调用**
         * KP 导出的 compat_strncpy_from_user（不 hook、零足迹）。
         * 安全性：本分支只在 x1≥0 时可达，而原生 getname 在该分支本来就会读 x0
         * ⇒ 这次读不产生任何新信号，只是把"范围内 vs 范围外"的耗时拉平。 */
        if (apk_eq_on && x0) {
            char tmp[APK_EQ_LEN];
            (void)compat_strncpy_from_user(tmp, (const char __user *)x0, APK_EQ_LEN);
            apk_n_eq++;
        }
        return APK_SAVED_CALL(regs, a0, a1, a2, a3, a4, a5);
    }

    /* ---- 4) cmd 在 supercall 范围内：仅"非受信任 uid + 非管理器形态"才开窗 ----
     *
     *   APatch 管理器的 supercall（uid 10266）形如
     *       NR 45 (x0=b400007232224080, x1=d0811581_1102, x2=..., x3=..., x4=..., x5=73)
     *   ⇒ x1 = 0xD0811581_XXXX：**高 32 位是非签名（管理器自带），cmd = 低 16 位**。
     *     它是 KP 的 trusted manager（免密钥通过，日志无 denied），
     *     **任何"替它做读取"的行为都会打断它的鉴权链** —— v0.5.3/v0.5.4 管理器失联
     *     就是 G1/G2 落在它的窗口里造成的。
     *   ⇒ 因此只有 x1 高 32 位为 0（普通小 cmd）且调用者非受信任 uid 时才开窗；
     *     管理器形态的调用**一律按原生路径走，一个字节都不干预**。
     *   （su 实测根本不调用 nr45，走 execve 魔法路径 ⇒ 天然与本模块无关。） */
    if (regs && (x1 >> 32) == 0 && !apk_uid_trusted())
        apk_win_task = current;
    apk_win_cnt++;
    apk_n_win++;

    ret = APK_SAVED_CALL(regs, a0, a1, a2, a3, a4, a5);

    apk_win_cnt--;
    apk_win_task = 0;
    return ret;
}

static int apk_install_latch(void)
{
    uintptr_t sct = (uintptr_t)kallsyms_lookup_name("sys_call_table");

    if (!sct)
        return 0;
    apk_sct = (uintptr_t *)sct;
    if (apk_sct[APK_NR_SUPERCALL] == (uintptr_t)apk_sc45_entry)
        return 0;

    /* fp_hook: *backup = 旧槽位值（KP 的 hook 链 transit），再把槽位换成我们 */
    fp_hook((uintptr_t)&apk_sct[APK_NR_SUPERCALL], (void *)apk_sc45_entry,
            (void **)&apk_saved45);
    if (!apk_saved45)
        return 0;
    apk_latch_installed = 1;
    APK_LOG("latch OK sct=%llx saved=%llx\n", (unsigned long long)sct,
            (unsigned long long)apk_saved45);
    return 1;
}

static void apk_uninstall_latch(void)
{
    unsigned long spins = 0;

    if (!apk_latch_installed)
        return;
    fp_unhook((uintptr_t)&apk_sct[APK_NR_SUPERCALL], (void *)apk_saved45);
    apk_latch_installed = 0;
    /* 排空在途窗口（回调仅微秒级，有界自旋即足够） */
    while (apk_win_cnt != 0 && spins < APK_DRAIN_LOOPS)
        spins++;
}

/* ==========================================================================
 * 三、G1/G2/G3 原语守卫
 * ========================================================================== */

/* G1：窗口内 memdup_user —— 源页不可用时返回全 0 缓冲
 *   与"真去读那块懒页"逐字节等价（懒页内容就是全 0），只是不产生缺页、
 *   不改动进程页表。源页可用 / 窗口外 → 原样调用原实现。 */
static void *apk_g1_memdup_user(const void __user *src, size_t len)
{
    if (apk_g1_on && apk_walk_ver && apk_win_cnt > 0 && apk_win_task == current &&
        !apk_uid_trusted() && src && len > 0 && len <= APK_MD_MAX) {
        if (apk_user_page_absent((uint64_t)src)) {
            void *p = apk_kmalloc ? apk_kmalloc(len, APK_GFP_KERNEL) : 0;
            apk_n_g1++;
            if (p) {
                apk_bzero(p, len);
                return p;
            }
            return ERR_PTR(-ENOMEM);
        }
        apk_n_g1_o++;
    }
    if (apk_orig_memdup_user)
        return apk_orig_memdup_user(src, len);
    return ERR_PTR(-ENOMEM);
}

/* G2：compat_strncpy_from_user —— 只在本任务的 nr45 窗口内、"源页不可无痕访问"时
 *      返回 0（KP 侧 `if (len <= 0) return;` 恰好就是"读不到"的正常分支）。
 *
 *  事故修复（这四道门必须保留）：
 *   修好 MAIR 之后遍历变可用，而当时的 G2 **没有窗口/身份门控**，会对
 *   全系统每一次 compat_strncpy_from_user 做判断。问题在于「合法但尚未换入的
 *   懒分配页」在原实现下会被正常缺页换入并读到内容，而 G2 却把它判成"不可用"
 *   直接返回 0 == **静默吃掉合法读取**。后果：
 *     · su / APatch 管理器的密钥读取（走 execve 的 sucompat / supercmd 路径）
 *       被吃掉 ⇒ 鉴权失败 ⇒ 管理器连不上、`su -c` 不升权；
 *     · 顺带把检测器也骗过（KP 没读到懒页 ⇒ 该页不被换入）——
 *       "检测没了但管理器也废了"其实是同一个根因。
 *   ⇒ 现在四道门：窗口内 + 本任务 + **非受信任 uid** + 遍历已被 oracle 证实。
 *      root / 管理器 / su（受信任）在全系统范围内永不受本函数影响。 */
static long apk_g2_scfu(char *dest, const char __user *src, long count)
{
    if (apk_g2_on && apk_walk_ver && apk_win_cnt > 0 && apk_win_task == current &&
        !apk_uid_trusted() && src && count > 0 &&
        apk_user_page_absent((uint64_t)src)) {
        apk_n_g2++;
        return 0;
    }
    return apk_orig_scfu(dest, src, count);
}

/* G3：compat_copy_to_user —— 目的页不可用时不做拷贝，按成功返回
 *   默认关闭：合法客户端可能传入刚 mmap、尚未触碰的接收缓冲。 */
static int apk_g3_c2u(void __user *to, const void *from, int n)
{
    if (apk_g3_on && apk_walk_ver && apk_win_cnt > 0 && apk_win_task == current &&
        !apk_uid_trusted() && to && n > 0 &&
        apk_user_page_absent((uint64_t)to)) {
        apk_n_g3++;
        return n;
    }
    return apk_orig_c2u(to, from, n);
}

/* ==========================================================================
 * 安装 / 卸载
 * ========================================================================== */

static int apk_install_guards(void)
{
    uintptr_t fn;
    hook_err_t err;

    /* G1（默认关 → 不挂全局原语钩，零系统级足迹） */
    if (apk_g1_on) {
        fn = (uintptr_t)kallsyms_lookup_name("memdup_user");
        if (fn) {
            err = hook((void *)fn, (void *)apk_g1_memdup_user,
                       (void **)&apk_orig_memdup_user);
            if (err) {
                APK_LOG("G1 hook failed: %d\n", (int)err);
                apk_g1_on = 0;
            }
        } else {
            apk_g1_on = 0;
        }
    }
    apk_kmalloc = (void *(*)(size_t, unsigned int))kallsyms_lookup_name("__kmalloc");
    apk_kfree = (void (*)(const void *))kallsyms_lookup_name("kfree");

    /* G2（默认关 → 同样不挂；见文件上方说明） */
    if (apk_g2_on) {
        err = hook((void *)compat_strncpy_from_user, (void *)apk_g2_scfu,
                   (void **)&apk_orig_scfu);
        if (err) {
            APK_LOG("G2 hook failed: %d\n", (int)err);
            apk_g2_on = 0;
        }
    }

    /* G3（可选） */
    if (apk_g3_on) {
        err = hook((void *)compat_copy_to_user, (void *)apk_g3_c2u,
                   (void **)&apk_orig_c2u);
        if (err) {
            APK_LOG("G3 hook failed: %d\n", (int)err);
            apk_g3_on = 0;
        }
    }

    return (apk_g1_on || apk_g2_on || apk_g3_on) ? 1 : 0;
}

static void apk_uninstall_guards(void)
{
    if (apk_orig_memdup_user) {
        unhook((void *)(uintptr_t)kallsyms_lookup_name("memdup_user"));
        apk_orig_memdup_user = 0;
    }
    if (apk_orig_scfu) {
        unhook((void *)compat_strncpy_from_user);
        apk_orig_scfu = 0;
    }
    if (apk_orig_c2u) {
        unhook((void *)compat_copy_to_user);
        apk_orig_c2u = 0;
    }
}

static long apk_init(const char *args, const char *event, void *reserved)
{
    (void)args;
    (void)event;
    (void)reserved;

    apk_printk = (int (*)(const char *, ...))kallsyms_lookup_name("printk");
    if (!apk_printk)
        apk_printk = (int (*)(const char *, ...))kallsyms_lookup_name("_printk");
    apk_snprintf = (int (*)(char *, size_t, const char *, ...))kallsyms_lookup_name("scnprintf");
    if (!apk_snprintf)
        apk_snprintf = (int (*)(char *, size_t, const char *, ...))kallsyms_lookup_name("snprintf");
    apk_nofault_r = (long (*)(void *, const void *, size_t))kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!apk_nofault_r)
        apk_nofault_r = (long (*)(void *, const void *, size_t))kallsyms_lookup_name("probe_kernel_read");
    apk_copy_to_user = (long (*)(void *, const void *, unsigned long))kallsyms_lookup_name("copy_to_user");
    if (!apk_copy_to_user)
        apk_copy_to_user = (long (*)(void *, const void *, unsigned long))kallsyms_lookup_name("_copy_to_user");

    if (!apk_nofault_r) {
        APK_LOG("init: no nofault reader → walk unavailable\n");
    }

    apk_install_guards();          /* 先装原语钩子（兜底标定要用 memdup_user trampoline） */
    apk_user_params_from_tcr();    /* 用户侧 VA 位宽/页大小来自 TCR_EL1，确定性推导 */
    apk_mair = apk_mrs_mair();
    apk_walk_ok = apk_calib_kimage();      /* 路径 A：kimage_voffset + 内容比对（不依赖遍历） */
    if (!apk_walk_ok)
        apk_walk_ok = apk_calib_kernel();  /* 路径 B：TTBR1 页表遍历 + 内容比对（兜底） */
    if (apk_walk_ok)
        apk_refresh_upgd();
    if (apk_latch_on)
        apk_install_latch();       /* 最后装槽位（它是最外层） */

    APK_LOG("init done alw=%d mair=%llx latch=%d g1=%d g2=%d g3=%d walk=%d lin=%llx u%d ps%d lv%d\n",
            apk_allow_n,
            (unsigned long long)apk_mair,
            apk_latch_installed, apk_g1_on, apk_g2_on, apk_g3_on, apk_walk_ok,
            (unsigned long long)apk_lin_off, apk_ubits, apk_ups, apk_ulevel);
    return 0;
}

static long apk_exit(void *reserved)
{
    (void)reserved;

    /* 停机顺序（内存安全优先；模块 .text 在 kpm_exit 返回后即被释放）：
     * 1) 摘槽位 → 不再有新窗口进入，并排空在途窗口
     * 2) 再排空一次（覆盖摘除瞬间已在途的调用）
     * 3) 摘原语钩子（此刻已无窗口内的偏离分支） */
    apk_uninstall_latch();
    apk_g1_on = 0;
    apk_g2_on = 0;
    apk_g3_on = 0;
    apk_eq_on = 0;
    apk_uninstall_guards();

    APK_LOG("exit done\n");
    return 0;
}

/* ==========================================================================
 * 五、KPM_CTL0 状态接口
 *   status / info      ：输出一行状态串
 *   g1=0|1 g2=0|1      ：运行时开关读侧守卫
 *   g3=0|1             ：运行时开关写侧守卫（打开会即时挂钩）
 *   eq=0|1             ：时延均衡
 *   latch=0|1          ：槽位前置（关掉即整模块待机）
 *   recal              ：清空标定，等下次窗口重做自标定
 *   walk=<hex>         ：手动指定线性映射偏移并强制标定（排障用）
 * ========================================================================== */

static void apk_status_line(char *buf, int buflen)
{
    char hx1[20], hx2[20], hx3[20];

    if (!buf || buflen <= 0)
        return;
    buf[0] = '\0';
    if (!apk_snprintf)
        return;

    apk_hex64(hx1, apk_lin_off);
    apk_hex64(hx2, (uint64_t)(uintptr_t)apk_sct);
    apk_hex64(hx3, apk_mair);

    apk_snprintf(buf, (size_t)buflen,
                 "APKey_Hide v0.5.4 neg=%u x1n=%d ver=%d alw=%d latch=%d "
                 "g1=%d g2=%d g3=%d "
                 "eq=%d walk=%d mair=%s lin=%s upgd=%d ubits=%d ups=%d sct=%s saved=%d "
                 "blk=%u win=%u md=%u mdo=%u scfu=%u c2u=%u eqn=%u abs=%u",
                 (unsigned)apk_n_neg, apk_x1neg_on, apk_walk_ver, apk_allow_n,
                 apk_latch_installed, apk_g1_on, apk_g2_on, apk_g3_on, apk_eq_on,
                 apk_walk_ok, hx3, hx1, (int)(apk_upgd != 0), apk_ubits, apk_ups, hx2,
                 (int)(apk_saved45 != 0),
                 (unsigned)apk_n_blk, (unsigned)apk_n_win, (unsigned)apk_n_g1,
                 (unsigned)apk_n_g1_o, (unsigned)apk_n_g2, (unsigned)apk_n_g3,
                 (unsigned)apk_n_eq, (unsigned)apk_n_absent);
    buf[buflen - 1] = '\0';
}

long apk_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char cmd[24];
    char out[320];
    int n = 0;

    if (args) {
        while (args[n] && n < (int)sizeof(cmd) - 1) {
            cmd[n] = args[n];
            n++;
        }
    }
    cmd[n] = '\0';

    if (n > 0) {
        if (apk_str_prefix(cmd, "allow=")) {
            /* allow=0 / allow=0,2000 / allow=none —— 受信任调用者白名单 */
            const char *q = cmd + 6;
            apk_allow_n = 0;
            if (!(q[0] == 'n')) {
                while (*q && apk_allow_n < APK_ALLOW_MAX) {
                    uint32_t v = 0;
                    while (*q >= '0' && *q <= '9')
                        v = v * 10u + (uint32_t)(*q++ - '0');
                    apk_allow[apk_allow_n++] = v;
                    if (*q == ',')
                        q++;
                    else
                        break;
                }
            }
        } else if (apk_str_prefix(cmd, "x1neg=")) {
            apk_x1neg_on = (cmd[6] == '1');
        } else if (apk_str_prefix(cmd, "g1=")) {
            apk_g1_on = (cmd[3] == '1');
        } else if (apk_str_prefix(cmd, "g2=")) {
            apk_g2_on = (cmd[3] == '1');
        } else if (apk_str_prefix(cmd, "g3=")) {
            int want = (cmd[3] == '1');
            if (want && !apk_g3_on && apk_orig_c2u == 0) {
                hook_err_t err = hook((void *)compat_copy_to_user, (void *)apk_g3_c2u,
                                      (void **)&apk_orig_c2u);
                apk_g3_on = err ? 0 : 1;
            } else if (!want && apk_g3_on) {
                unhook((void *)compat_copy_to_user);
                apk_orig_c2u = 0;
                apk_g3_on = 0;
            }
        } else if (apk_str_prefix(cmd, "eq=")) {
            apk_eq_on = (cmd[3] == '1');
        } else if (apk_str_prefix(cmd, "latch=")) {
            int want = (cmd[6] == '1');
            if (want && !apk_latch_installed)
                apk_install_latch();
            else if (!want && apk_latch_installed)
                apk_uninstall_latch();
        } else if (apk_str_eq(cmd, "recal")) {
            apk_walk_ok = 0;
            apk_walk_ver = 0;            /* 守卫下线，等 oracle 重新证实 */
            apk_st_done = 0;
            apk_upgd = 0;
        } else if (apk_str_prefix(cmd, "walk=")) {
            /* 排障：手动指定线性偏移，下次窗口直接用（跳过内容比对） */
            apk_lin_off = apk_hex2u64(cmd + 5);
            apk_ubits = 39;
            apk_ups = 12;
            apk_ulevel = (apk_ubits - 4) / (apk_ups - 3);
            apk_mair = apk_mrs_mair();
            apk_refresh_upgd();
            apk_walk_ok = (apk_upgd != 0);
            apk_st_done = 1;
        }
        /* 其余（含 status / info / 空命令）统一落到状态输出 */
    }

    apk_status_line(out, (int)sizeof(out));
    if (out_msg && outlen > 0 && apk_copy_to_user) {
        int len = 0;
        while (out[len] && len < outlen - 1)
            len++;
        if (len > 0)
            (void)apk_copy_to_user(out_msg, out, (unsigned long)(len + 1));
    }
    return 0;
}

/* ========================== 入口注册 ========================== */
KPM_CTL0(apk_ctl0);

static long apk_init_impl(const char *args, const char *event, void *reserved)
{
    return apk_init(args, event, reserved);
}

static long apk_exit_impl(void *reserved)
{
    return apk_exit(reserved);
}

KPM_INIT(apk_init_impl);
KPM_EXIT(apk_exit_impl);
