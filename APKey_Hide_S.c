/*
 * APKey_Hide_S —— APatch / KernelPatch supercall 隐藏（自杀模式）
 *
 *   模块名 : APKey_HideS   （与标准版 APKey_Hide 同存，但【绝不同时加载】）
 *   版  本 : 2.2.0s（机制改版：.bak 槽位前置 + 全旁路，弃 G2/标定/学习全家桶）
 *   作  者 : Lun.
 *   许  可 : MIT
 *   平  台 : Android arm64（KernelPatch / APatch 之上）
 *
 * ==========================================================================
 * 自杀模式：不采信任何鉴权 —— 也不【观察】任何鉴权
 * ==========================================================================
 * 我已绝望，大牛我服了，n那就杀死比赛吧
 * ==========================================================================
   不要永久嵌入；To be embedded permanently
 
 */



/***
 * _ooOoo_
 * o8888888o
 * 88" . "88
 * (| -_- |)
 *  O\ = /O
 * ___/`---'\____
 * .   ' \\| |// `.
 * / \\||| : |||// \
 * / _||||| -:- |||||- \
 * | | \\\ - /// | |
 * | \_| ''\---/'' | |
 * \ .-\__ `-` ___/-. /
 * ___`. .' /--.--\ `. . __
 * ."" '< `.___\_<|>_/___.' >'"".
 * | | : `- \`.;`\ _ /`;.`/ - ` : | |
 * \ \ `-. \_ __\ /__ _/ .-` / /
 * ======`-.____`-.___\_____/___.-`____.-'======
 * `=---='
 *          .............................................
 *           佛曰：bug泛滥，我已瘫痪！
 */




#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <common.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <kputils.h>          /* current_uid */
#include <hook.h>             /* fp_hook / fp_unhook */
#include <ksyms.h>
#include <kallsyms.h>
#include <baselib.h>
#include <asm/ptrace.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("APKey_HideS");
KPM_VERSION("114514.0.0");
KPM_LICENSE("MIT");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("不要永久嵌入！To be embedded permanently！;bypass KP for non-root nr45 entirely [SUICIDE];https://github.com/Lun-OS/APKey_Hide_KPM");

/* ========================== 常量 ========================== */
#define APK_NR_SUPERCALL    45           /* __NR_supercall（arm64 与 truncate 同号） */
#define APK_CMD_MIN         0x1000       /* SUPERCALL_HELLO（仅 trace/status 展示用） */
#define APK_CMD_MAX         0x1200       /* SUPERCALL_MAX */
#define APK_DRAIN_LOOPS     400000000UL  /* 卸载排空上限（在途调用为微秒级） */

/* ========================== 日志（release 零 dmesg 痕迹） ========================== */
static int (*apk_printk)(const char *fmt, ...);

#ifdef APK_DEBUG_LOG
#define APK_LOG(fmt, ...)                                                    \
    do {                                                                     \
        if (apk_printk)                                                      \
            apk_printk("[APKey_HideS] " fmt, ##__VA_ARGS__);                 \
    } while (0)
#else
#define APK_LOG(fmt, ...) do { } while (0)
#endif

/* ========================== 可调参数 ========================== */
static int apk_bypass_on = 1;   /* 总开关（ctl0 唯一可改面；关掉=纯透传待机） */
static int apk_trace;           /* ctl0 trace=1：nr45 现场记录（debug 版） */

/* ========================== 自杀式信任 ==========================
 * 信任集 = 仅内核 uid 0（apd / root shell）。uid 由内核赋予、调用方无法伪造
 * —— 这是身份事实，不是鉴权采信。没有学习、没有白名单、没有 KP 裁决观察。 */
static int apk_trusted_s(uint32_t u)
{
    return u == 0;
}

/* ========================== 运行时解析的内核侧符号 ========================== */
static int  (*apk_snprintf)(char *buf, size_t sz, const char *fmt, ...);
static long (*apk_copy_to_user)(void *to, const void *from, unsigned long n);

/* KernelPatch 导出符号（由 KPM 加载器解析；与 .bak 相同的 extern 写法） */
extern int has_syscall_wrapper;

/* 原生 nr45（truncate）入口 —— 旁路的落点 */
static uintptr_t apk_orig45;

/* 槽位前置状态 */
static uintptr_t *apk_sct;
static uintptr_t  apk_saved45;           /* 被接管前槽位值（KP 链 transit） */
static int        apk_latch_installed;

/* 在途 entry 计数（卸载排空；防 .text 释放后仍执行 ⇒ UAF panic）。
 * 必须原子：不用 __atomic/__sync 系列（libgcc 辅助符号 ⇒ KPM 加载失败），
 * 与 LH_Dr_KPM 相同用 ldaxr/stlxr 裸汇编。 */
static volatile int apk_entry_inflight;

static inline void apk_atomic_inc(volatile int *p)
{
    int old, newv, ret;
    asm volatile(
        "1: ldaxr %w[old], %[mem]\n"
        "   add   %w[new], %w[old], #1\n"
        "   stlxr %w[ret], %w[new], %[mem]\n"
        "   cbnz  %w[ret], 1b\n"
        : [old] "=&r"(old), [new] "=&r"(newv), [ret] "=&r"(ret),
          [mem] "+Q"(*p) :: "memory");
}

static inline void apk_atomic_dec(volatile int *p)
{
    int old, newv, ret;
    asm volatile(
        "1: ldaxr %w[old], %[mem]\n"
        "   sub   %w[new], %w[old], #1\n"
        "   stlxr %w[ret], %w[new], %[mem]\n"
        "   cbnz  %w[ret], 1b\n"
        : [old] "=&r"(old), [new] "=&r"(newv), [ret] "=&r"(ret),
          [mem] "+Q"(*p) :: "memory");
}

/* ========================== 计数（status） ========================== */
static volatile uint32_t apk_n_pass;     /* uid0 → KP 链 */
static volatile uint32_t apk_n_byp;      /* 非 uid0 → 原生 truncate 旁路 */
static volatile uint32_t apk_n_fb;       /* 旁路降级（orig45 解析失败的兜底） */
static volatile uint32_t apk_n_off;      /* 待机透传（bypass_on=0） */

/* ==========================================================================
 * 槽位前置入口：接管 sys_call_table[45]
 *   签名与 .bak 相同：非 wrapper 模式收到 a0..a5=寄存器；
 *   wrapper 模式 a0=内核栈上的 pt_regs*（直接解引用安全：syscall 上下文）。
 * ========================================================================== */
#define APK_KPCALL(fp, regs, a0, a1, a2, a3, a4, a5)                           \
    (has_syscall_wrapper                                                       \
         ? ((long (*)(struct pt_regs *))(fp))(regs)                             \
         : ((long (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,        \
                      uint64_t))(fp))(a0, a1, a2, a3, a4, a5))

static long apk_sc45_entry(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                           uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    struct pt_regs *regs = 0;
    uint64_t x0, x1, cmd;
    uint32_t uid;
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

    (void)x0;                              /* 仅 trace 分支使用（release 版消除） */
    (void)cmd;

    apk_atomic_inc(&apk_entry_inflight);
    uid = (uint32_t)current_uid();

    if (apk_trace)
        APK_LOG("t uid=%u x0=%llx x1=%llx cmd=%llx\n", (unsigned)uid,
                (unsigned long long)x0, (unsigned long long)x1,
                (unsigned long long)cmd);

    if (!apk_bypass_on) {                  /* 待机：纯透传（等价于不装本模块） */
        apk_n_off++;
        ret = APK_KPCALL(apk_saved45, regs, a0, a1, a2, a3, a4, a5);
        goto out;
    }

    if (apk_trusted_s(uid)) {              /* uid0：完整 KP 链，功能零回归 */
        apk_n_pass++;
        ret = APK_KPCALL(apk_saved45, regs, a0, a1, a2, a3, a4, a5);
        goto out;
    }

    /* ★核心旁路：非 uid0 —— 原生 truncate 同参数直接执行。
     * KP 的 before()/链/鉴权/分发对这次调用一概不发生：
     *   · 返回值 = 干净内核返回值（由真实现算出，无净化需求，无伪造面）；
     *   · x0/x2/x3 的用户页读取 = 干净内核的读取集合（x1<0 时零字节，
     *     x1>=0 时 getname 正常读 —— 与检测器的 Read control 完全一致）；
     *   · 检测器无论怎么布置懒页/时序，看到的都是"这台机器没装 KP"。 */
    if (apk_orig45) {
        ret = APK_KPCALL(apk_orig45, regs, a0, a1, a2, a3, a4, a5);
    } else {
        /* 极端兜底：原生入口解析失败。宁可按干净内核语义编一个合法错误，
         * 也绝不放非 uid0 进 KP 链（自杀模式的取舍与标准版相反：
         * 这里 fail-closed 是安全侧，标准版才 fail-open）。 */
        ret = ((long)x1 < 0) ? -EINVAL : -ENOENT;
        apk_n_fb++;
    }
    apk_n_byp++;
    if (apk_n_byp <= 8)                    /* 前 8 次留痕（debug 版） */
        APK_LOG("byp uid=%u x1=%llx -> %ld\n", (unsigned)uid,
                (unsigned long long)x1, ret);

out:
    apk_atomic_dec(&apk_entry_inflight);
    return ret;
}

/* ==========================================================================
 * 槽位安装 / 摘除（与 .bak 的 L0 完全同构）
 * ========================================================================== */
static int apk_install_latch(void)
{
    uintptr_t sct = (uintptr_t)kallsyms_lookup_name("sys_call_table");

    if (!sct)
        return 0;
    apk_sct = (uintptr_t *)sct;
    if (apk_sct[APK_NR_SUPERCALL] == (uintptr_t)apk_sc45_entry)
        return 1;                          /* 已装（幂等） */

    /* fp_hook: *backup = 旧槽位值（KP 链 transit），再把槽位换成我们 */
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
    /* 摘槽不影响"已分发进 entry"的在途调用 ⇒ 排空后模块 .text 才可释放 */
    while (apk_entry_inflight != 0 && spins < APK_DRAIN_LOOPS)
        spins++;
    if (apk_entry_inflight != 0)
        APK_LOG("exit: inflight NOT drained (%d)\n", apk_entry_inflight);
}

/* ==========================================================================
 * 控制面（ctl0 —— 仅 uid0 可达：非 root 的 supercall 已被旁路）
 *   status / info   ：状态串
 *   bypass=0|1      ：总开关（0=纯透传待机）
 *   trace=0|1       ：现场日志（debug 版）
 * 无 allow=/learn=/reset=/g2=：本模式不存在任何可引入的"信任面"。
 * ========================================================================== */
static int apk_str_prefix(const char *s, const char *p)
{
    while (*p) {
        if (*s++ != *p++)
            return 0;
    }
    return 1;
}

static void apk_status_line(char *buf, int buflen)
{
    if (!buf || buflen <= 0)
        return;
    buf[0] = '\0';
    if (!apk_snprintf)
        return;

    apk_snprintf(buf, (size_t)buflen,
                 "APKey_HideS v2.2.0s [SUICIDE] latch=%d bypass=%d trace=%d "
                 "o45=%llx saved=%llx n(pass=%u byp=%u fb=%u off=%u)",
                 apk_latch_installed, apk_bypass_on, apk_trace,
                 (unsigned long long)apk_orig45,
                 (unsigned long long)apk_saved45,
                 (unsigned)apk_n_pass, (unsigned)apk_n_byp,
                 (unsigned)apk_n_fb, (unsigned)apk_n_off);
    buf[buflen - 1] = '\0';
}

long apk_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char cmd[24];
    char out[256];
    int n = 0;

    if (args) {
        while (args[n] && n < (int)sizeof(cmd) - 1) {
            cmd[n] = args[n];
            n++;
        }
    }
    cmd[n] = '\0';

    if (n > 0) {
        if (apk_str_prefix(cmd, "bypass=")) {
            apk_bypass_on = (cmd[7] == '1');
        } else if (apk_str_prefix(cmd, "trace=")) {
            apk_trace = (cmd[6] == '1');
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

KPM_CTL0(apk_ctl0);

/* ==========================================================================
 * 安装 / 卸载
 * ========================================================================== */
static void apk_resolve_orig45(void)
{
    apk_orig45 = (uintptr_t)kallsyms_lookup_name("__arm64_sys_truncate");
    if (!apk_orig45)
        apk_orig45 = (uintptr_t)kallsyms_lookup_name("__se_sys_truncate");
    if (!apk_orig45)
        apk_orig45 = (uintptr_t)kallsyms_lookup_name("__do_sys_truncate");
    if (!apk_orig45)
        apk_orig45 = (uintptr_t)kallsyms_lookup_name("SyS_truncate");
    if (!apk_orig45)
        apk_orig45 = (uintptr_t)kallsyms_lookup_name("sys_truncate");
}

static long apk_init(const char *args, const char *event, void *reserved)
{
    (void)args;
    (void)event;
    (void)reserved;

    apk_printk = (int (*)(const char *, ...))kallsyms_lookup_name("printk");
    if (!apk_printk)
        apk_printk = (int (*)(const char *, ...))kallsyms_lookup_name("_printk");
    apk_snprintf = (int (*)(char *, size_t, const char *, ...))
        kallsyms_lookup_name("scnprintf");
    if (!apk_snprintf)
        apk_snprintf = (int (*)(char *, size_t, const char *, ...))
            kallsyms_lookup_name("snprintf");
    apk_copy_to_user = (long (*)(void *, const void *, unsigned long))
        kallsyms_lookup_name("copy_to_user");
    if (!apk_copy_to_user)
        apk_copy_to_user = (long (*)(void *, const void *, unsigned long))
            kallsyms_lookup_name("_copy_to_user");

    apk_resolve_orig45();
    if (!apk_orig45)
        APK_LOG("init: native truncate UNRESOLVED (fallback mode)\n");

    if (!apk_install_latch()) {
        APK_LOG("init: latch failed (no sys_call_table?) -> module idle\n");
        return -1;
    }

    APK_LOG("init v2.2.0s SUICIDE done o45=%llx wrapper=%d\n",
            (unsigned long long)apk_orig45, has_syscall_wrapper);
    return 0;
}

static long apk_exit(void *reserved)
{
    (void)reserved;

    /* 先置待机（在途调用即使还在也不会走偏离分支），再摘槽并排空 */
    apk_bypass_on = 0;
    apk_uninstall_latch();

    APK_LOG("exit done\n");
    return 0;
}

KPM_INIT(apk_init);
KPM_EXIT(apk_exit);
