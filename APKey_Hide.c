/*
 * APKey_Hide —— 让 KernelPatch 的 supercall 接口对非受信调用者不可观测
 *
 *   模块名 : APKey_Hide
 *   版  本 : 3.2.0
 *   作  者 : Lun.
 *   许  可 : MIT
 *   平  台 : Android arm64（KernelPatch / APatch / 派生分支之上）
 *
 * ==========================================================================
 * 设计（v3.2.4：钩住 KP 的排除判定函数，按调用者当场裁决）
 * ==========================================================================
 * v3.1 的区间枚举排除有一个已被真机实测证实的漏洞：它只能排除"当前已知的
 * uid 区间"。实测：区间 [1,20000) 排除后，uid=90000（Android isolatedProcess
 * 就是这一段的）依然拿到 `key=[su]` —— 一个没有 root 的普通应用只要用
 * isolatedProcess 起一个 service 就换到全新 uid，直接读走真实 superkey。
 * 任何"枚举区间"的写法都追不上 uid 空间的形态（isolated 9xxxx、多用户 10xxxx）。
 *
 * v3.2 改为**在 KP 的判定函数上当场裁决**：
 *
 *   KP 的 supercall before() 第一行是
 *       int uid = current_uid();
 *       if (get_ap_mod_exclude(uid)) return;      ← supercall.c:391-393
 *   本模块 inline hook 掉 KP 导出的 get_ap_mod_exclude(uid)：
 *       · 受信 uid（下面定义的信任集）→ 返回原值 0（放行，KP 照常鉴权）
 *       · 其余所有 uid（含 9xxxx isolated、10xxxx 多用户、未来任何新段）
 *         → 直接返回 1 ⇒ KP 立刻 return：不读 key、不鉴权、不分发、
 *           不写缓冲区、不产生任何副作用；调用者看到的就是原生 truncate
 *           语义（例如 syscall(45, "su", 0x100a) → -ENOENT，与无 KP 的
 *           内核完全一致）。
 *
 * 信任集 = { uid 0（root，恢复通道） }
 *        ∪ { 加载者（仅在特权域完成一次精确修正之前临时放行） }
 *        ∪ { 名字校验过的管理器（按 packages.list 的 包名↔uid 映射确定） }
 *        ∪ { ctl0 allow= 显式放行的 uid（逃生口） }
 *
 * 为什么这样不可检测（逐条对应此前红队清单）：
 *   V1 缓冲区取证：KP 在读 key 之前就返回 ⇒ 不会写任何调用者缓冲区。
 *   V2 KPM 枚举：模块列表本身就是 KP 的，本模块不新增可枚举面。
 *   V3 自我授权：非受信者一律被排除，伪造请求只会得到原生语义。
 *   V4 副作用 oracle：无鉴权、无分发、无日志（release 版零 printk）。
 *   V5 ctl0：非信任集到不了（KP 直接 -EPERM；本模块 ctl0 亦按信任集准入）。
 *   V6 页信道：key 页不会被换入。
 *   V7 返回值 oracle：返回原生 truncate 语义。
 *   ★uid 维度：不再依赖"枚举哪些 uid"，因此 isolatedProcess / 多用户 /
 *     未来新 uid 段全部天然覆盖 —— 这是 v3.1 → v3.2 的核心修复。
 *
 * 符号面（均已在真机 boot 镜像的 KP 导出表里实测存在）：
 *   get_ap_mod_exclude / set_ap_mod_exclude / hook / unhook / current_uid；
 *   printk / scnprintf / copy_to_user / vmalloc / vfree / filp_open /
 *   kernel_read / filp_close 走 kallsyms 运行时解析，缺失只降级。
 *
 * 已知边界（诚实）：
 *   · 排除是 kstorage/hook 级状态 ⇒ 每 boot 重来一次，需每次开机重新加载；
 *   · 管理器身份依赖 packages.list（只有特权域读得了）⇒ 管理员加载模块时
 *     init 不做修正，"加载者"先按临时信任放行，等 root 域的一次 supercall
 *     （例如 root 跑任何 KP 命令）自动完成修正；修正后加载者不再是管理器的
 *     话会被重新拒绝（堵掉"任何 app 抢先用公开钥匙加载一次即永久受信"）；
 *   · 文件层痕迹（.kpm 落在可读目录等）不在本模块职责内。
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
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>             /* hook() / unhook() */
#include <baselib.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("APKey_Hide");
KPM_VERSION("3.2.0");
KPM_LICENSE("MIT");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("不要嵌入boot!Don't embed boot!;https://github.com/Lun-OS/APKey_Hide_KPM");

/* ========================== 常量 ========================== */
/* 降级模式（钩子装不上时）用的区间：system 段 + user0 应用段 + isolated 段。
 * 实测依据：adb(2000) 用公开钥匙可读走真实 superkey（SKEY_GET）—— 这正是
 * "发现 AP 密钥"的通道；排除 2000 后 SKEY_GET/kpver/KPM_LIST 全部 ENOENT，
 * 且 `su -c id` 仍为 uid=0（su 走 execve 钩子，不经 supercall）。 */
#define APK_AID_APP_START   10000u          /* 应用段起点 */
#define APK_AID_EXCL_START  1u
#define APK_AID_EXCL_END    20000u
#define APK_AID_ISO_START   90000u          /* Android isolatedProcess 段 */
#define APK_AID_ISO_END     100000u
#define APK_PKGL_PATH       "/data/system/packages.list"
#define APK_PKGL_MAX        (256UL << 10)
#define APK_MGR_NAME_MAX    6               /* 已知管理器包名槽位 */
#define APK_ALLOW_MAX       8               /* ctl0 allow= 逃生口槽位 */
#define APK_REFINE_MAX_TRY  4               /* 特权域修正的最大尝试次数 */

/* ========================== 日志 ========================== */
static int (*apk_printk)(const char *fmt, ...);

#ifdef APK_DEBUG_LOG
#define APK_LOG(fmt, ...)                                                    \
    do {                                                                     \
        if (apk_printk)                                                      \
            apk_printk("[APKey_Hide] " fmt, ##__VA_ARGS__);                  \
    } while (0)
#else
#define APK_LOG(fmt, ...) do { } while (0)
#endif

/* ========================== 符号 ========================== */
extern int  set_ap_mod_exclude(uid_t uid, int exclude);   /* KP 导出 */
extern int  get_ap_mod_exclude(uid_t uid);   /* KP 导出；v3.2 被本模块 inline hook */

static int   (*apk_snprintf)(char *, size_t, const char *, ...);
static long  (*apk_copy_to_user)(void *, const void *, unsigned long);
static void  *(*apk_vmalloc)(unsigned long);
static void  (*apk_vfree)(const void *);
static void  *(*apk_filp_open)(const char *, int, int);
static long  (*apk_kernel_read)(void *, void *, unsigned long, loff_t *);
static int   (*apk_filp_close)(void *, void *);

/* ========================== 状态 ========================== */
static uint32_t apk_loader_uid;            /* KPM_INIT 时的 current_uid() */
static int      apk_swept;                 /* 降级模式：区间排除已下 */
static int      apk_hook_ok;               /* v3.2 钩子安装成功 */
static uint32_t apk_mgr_uid;               /* 已确认的管理器 uid（0=未知） */
static int      apk_need_refine = 1;       /* 待特权域做一次精确修正 */
static uint32_t apk_mgr_uids[4];
static int      apk_mgr_cnt;
static uint32_t apk_allow_uids[APK_ALLOW_MAX];   /* ctl0 allow= 逃生口 */
static int      apk_allow_cnt;
static volatile uint32_t apk_n_deny;       /* 被钩子判为排除的调用数 */
static volatile uint32_t apk_n_pass;       /* 被钩子放行的调用数 */

/* 已知管理器包名（内置知识，非用户配置；可用 ctl0 mgrname= 追加） */
static const char *apk_mgr_names[APK_MGR_NAME_MAX] = {
    "me.yuki.folk",          /* FolkPatch 管理器 */
    "me.bmax.apatch",        /* 原版 APatch 管理器 */
    "com.example.apatch",
};

static int apk_name_is_mgr(const char *pkg)
{
    int i;
    for (i = 0; i < APK_MGR_NAME_MAX; i++) {
        const char *a = apk_mgr_names[i];
        const char *b = pkg;
        if (!a) continue;
        while (*a && *a == *b) { a++; b++; }
        /* packages.list 的包名字段以空格结束；包名本身不允许 ':' 等字符，
         * 这里只接受 字段结束符，避免前缀误匹配。 */
        if (!*a && (!*b || *b == ' ' || *b == '\n')) return 1;
    }
    return 0;
}

/* ========================== packages.list 读取 ==========================
 * ★调用方 SELinux 域限制（真机实测）：管理器(untrusted_app)加载模块时读该
 * 文件被拒（ERR_PTR(-EACCES)）⇒ 只在特权域（root/system）调用。 */
static char *apk_pkgl;
static unsigned apk_pkgl_len;
/* 非 0=正在修正。★刻意不用 __atomic / __sync 系列内建：arm64 上它们会生成
 * __aarch64_swp1_acq 之类 libgcc 辅助调用，而 KPM 的导入表里没有它们
 * ⇒ 模块会加载失败。这里是有意的"尽力而为"标志：极端竞态（两个 CPU 同时
 * 命中 root supercall）最坏结果是多读一次文件（管理器列表本身去重）、
 * 最多漏一个 256KB 缓冲；二选一都无害，且只在 boot 后一次性窗口内可能发生。 */
static volatile int apk_refining;

static int apk_load_pkglist(void)
{
    void *fp;
    loff_t pos = 0;
    long n;

    if (apk_pkgl)
        return 1;
    if (!apk_vmalloc || !apk_filp_open || !apk_kernel_read)
        return 0;
    fp = apk_filp_open(APK_PKGL_PATH, 0, 0);
    /* 内核指针转 long 是负数：不能用 <0 判错，只判 NULL 与 ERR_PTR 区间 */
    if (!fp || (unsigned long)fp >= (unsigned long)-4095UL) {
        APK_LOG("pkglist: open failed ptr=%llx (ctx uid=%u)\n",
                (unsigned long long)(unsigned long)fp, (unsigned)current_uid());
        return 0;
    }
    apk_pkgl = (char *)apk_vmalloc(APK_PKGL_MAX);
    if (!apk_pkgl) { if (apk_filp_close) apk_filp_close(fp, 0); return 0; }
    n = apk_kernel_read(fp, apk_pkgl, APK_PKGL_MAX - 1, &pos);
    if (apk_filp_close) apk_filp_close(fp, 0);
    if (n <= 0) {
        /* ★读失败必须回收，否则 256KB 缓冲泄漏且下次调用会误判"已加载" */
        APK_LOG("pkglist: read rc=%ld\n", n);
        if (apk_vfree) apk_vfree(apk_pkgl);
        apk_pkgl = 0;
        return 0;
    }
    apk_pkgl_len = (unsigned)n;
    apk_pkgl[apk_pkgl_len] = 0;
    APK_LOG("pkglist: read n=%u bytes\n", apk_pkgl_len);
    return 1;
}

/* 逐行处理：行格式 "<pkg> <uid> ..." */
static void apk_each_pkg(void (*cb)(const char *pkg, uint32_t uid, void *ud), void *ud)
{
    unsigned i = 0;
    if (!apk_pkgl) return;
    while (i < apk_pkgl_len) {
        unsigned e = i, j;
        uint32_t uid = 0;
        while (e < apk_pkgl_len && apk_pkgl[e] != '\n') e++;
        if (e > i + 2) {
            j = i;
            while (j < e && apk_pkgl[j] != ' ') j++;
            if (j < e) {
                unsigned k = j + 1;
                while (k < e && apk_pkgl[k] >= '0' && apk_pkgl[k] <= '9')
                    uid = uid * 10u + (uint32_t)(apk_pkgl[k++] - '0');
                if (uid) {
                    char pkg[64];
                    unsigned n = (j - i) < 63 ? (j - i) : 63;
                    for (k = 0; k < n; k++) pkg[k] = apk_pkgl[i + k];
                    pkg[n] = 0;
                    cb(pkg, uid, ud);
                }
            }
        }
        i = e + 1;
    }
}

/* ========================== 排除操作（降级模式用） ========================== */
static volatile uint32_t apk_n_excl, apk_n_unexcl, apk_n_skip;

static void apk_excl(uint32_t uid, int exclude)
{
    if (uid == 0) return;
    if (exclude) {
        if (get_ap_mod_exclude(uid)) { apk_n_skip++; return; }
        set_ap_mod_exclude(uid, 1);
        apk_n_excl++;
    } else {
        if (!get_ap_mod_exclude(uid)) return;
        set_ap_mod_exclude(uid, 0);
        apk_n_unexcl++;
    }
}

static void apk_sweep_span(uint32_t from, uint32_t to, int exclude)
{
    uint32_t u;
    for (u = from; u < to; u++) {
        if (exclude && u == apk_loader_uid)
            continue;                       /* 加载者默认放行（见 apk_trusted_uid） */
        apk_excl(u, exclude);
    }
}

/* ★仅降级模式（钩子装不上）调用：区间枚举无法覆盖全部 uid 段，属于"有洞的
 * 兜底"，正常路径（钩子成功）完全不写 kstorage。 */
static void apk_sweep_range(int exclude)
{
    apk_sweep_span(APK_AID_EXCL_START, APK_AID_EXCL_END, exclude);
    apk_sweep_span(APK_AID_ISO_START, APK_AID_ISO_END, exclude);
    apk_swept = exclude;
    APK_LOG("sweep(deg) [%u,%u)+[%u,%u) exclude=%d -> excl=%u skip=%u\n",
            APK_AID_EXCL_START, APK_AID_EXCL_END, APK_AID_ISO_START,
            APK_AID_ISO_END, exclude, (unsigned)apk_n_excl, (unsigned)apk_n_skip);
}

/* ② 精确修正：按 packages.list 的 包名↔uid 映射确定管理器 */
static void apk_refine_cb(const char *pkg, uint32_t uid, void *ud)
{
    int is_mgr = apk_name_is_mgr(pkg);
    (void)ud;
    if (is_mgr) {
        int i, dup = 0;
        for (i = 0; i < apk_mgr_cnt; i++)
            if (apk_mgr_uids[i] == uid) dup = 1;
        if (!dup && apk_mgr_cnt < 4) {
            apk_mgr_uids[apk_mgr_cnt++] = uid;
            if (!apk_mgr_uid) apk_mgr_uid = uid;
            APK_LOG("mgr confirmed uid=%u pkg=%s\n", (unsigned)uid, pkg);
        }
        /* 钩子模式下无需写 kstorage（判定在钩子里当场做）；
         * 降级模式必须解除管理器的排除，否则管理器会被自己扫出去。 */
        if (!apk_hook_ok)
            apk_excl(uid, 0);
        return;
    }
    /* 降级模式：非管理器应用补排除（含"不是管理器的加载者"） */
    if (!apk_hook_ok)
        apk_excl(uid, 1);
}

/* 特权域（root）里跑的一次修正；失败保留 need_refine（下次再试，最多 N 次） */
static void apk_refine(const char *why)
{
    static int tries;

    if (!apk_need_refine)
        return;
    if (tries >= APK_REFINE_MAX_TRY)
        return;
    /* 防重入：两个 CPU 同时命中 root supercall 时只让一个读文件 */
    if (apk_refining)
        return;
    apk_refining = 1;
    tries++;

    (void)why;                              /* release 版无日志，仅调试打印用 */
    if (!apk_load_pkglist()) {
        APK_LOG("refine(%s#%d): no packages.list -> 加载者保持临时信任\n",
                why, tries);
        apk_refining = 0;
        return;
    }
    APK_LOG("refine(%s#%d): scanning packages.list\n", why, tries);
    apk_each_pkg(apk_refine_cb, 0);
    apk_need_refine = 0;
    APK_LOG("refine done: mgr=%u cnt=%d loader=%u hook=%d\n",
            (unsigned)apk_mgr_uid, apk_mgr_cnt, (unsigned)apk_loader_uid,
            apk_hook_ok);
    apk_refining = 0;
}

static uint32_t apk_atou(const char *s)
{
    uint32_t v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10u + (uint32_t)(*s++ - '0');
    return v;
}

/* ==========================================================================
 * ★v3.2 核心：钩子主体（对任何 uid 当场裁决）
 *   受信 = uid 0 ∪ 显式放行(allow=) ∪ 加载者(修正前) ∪ 名字校验过的管理器
 *   其余一律 1（= 已排除）⇒ KP before() 立即 return：不读 key、不鉴权、
 *   不分发、无副作用。
 *   代价：本函数在 KP 的 NR45 钩子链里（原本 KP 自己也要在那里做一次
 *   kstorage 哈希查询），增量是十几个比较指令；未受信 uid 反而比"KP 查
 *   kstorage"更快返回，不会留下"更慢"的时序指纹。
 * ========================================================================== */
static int (*apk_orig_get_excl)(uid_t uid);

static int apk_trusted_uid(uint32_t u)
{
    int i;
    if (u == 0)                                     /* root：恢复通道 */
        return 1;
    for (i = 0; i < apk_allow_cnt; i++)
        if (apk_allow_uids[i] == u) return 1;        /* ctl0 allow= 逃生口 */
    for (i = 0; i < apk_mgr_cnt; i++)
        if (apk_mgr_uids[i] == u) return 1;          /* 名字校验过的管理器 */
    /* 加载者：仅在特权域修正完成前临时放行。
     * 修正后仍受信 ⇔ 它确实是被 packages.list 证实的管理器（在前一循环里）；
     * 否则（例如某个 app 抢先用公开钥匙加载）在此被重新拒绝。 */
    if (apk_loader_uid && u == apk_loader_uid && apk_need_refine)
        return 1;
    return 0;
}

static int apk_get_excl_hook(uid_t uid)
{
    uint32_t u = (uint32_t)uid;

    /* 第一次见到 root 的 supercall ⇒ 在 root 域里做一次精确修正
     * （只有特权域读得了 /data/system/packages.list） */
    if (u == 0 && apk_need_refine)
        apk_refine("hook-uid0");

    if (apk_trusted_uid(u)) {
        apk_n_pass++;
        return 0;                       /* 放行：KP 继续原有鉴权流程 */
    }
    apk_n_deny++;
    if (apk_n_deny <= 8)
        APK_LOG("hook-deny uid=%u\n", (unsigned)u);
    return 1;                           /* 视为已排除：KP 立即返回，零副作用 */
}

/* ========================== ctl0（按信任集准入） ========================== */
static int apk_str_prefix(const char *s, const char *p)
{
    while (*p) { if (*s++ != *p++) return 0; }
    return 1;
}

static void apk_status_line(char *buf, int buflen)
{
    if (!buf || buflen <= 0) return;
    buf[0] = 0;
    if (!apk_snprintf) return;
    apk_snprintf(buf, (size_t)buflen,
                 "APKey_Hide v3.2.0 hook=%d swept=%d loader=%u mgr=%u "
                 "need_refine=%d allow=%d deny=%u pass=%u "
                 "n(excl=%u unexcl=%u skip=%u) names=%s,%s,%s",
                 apk_hook_ok, apk_swept, (unsigned)apk_loader_uid,
                 (unsigned)apk_mgr_uid, apk_need_refine, apk_allow_cnt,
                 (unsigned)apk_n_deny, (unsigned)apk_n_pass,
                 (unsigned)apk_n_excl, (unsigned)apk_n_unexcl,
                 (unsigned)apk_n_skip,
                 apk_mgr_names[0] ? apk_mgr_names[0] : "-",
                 apk_mgr_names[1] ? apk_mgr_names[1] : "-",
                 apk_mgr_names[2] ? apk_mgr_names[2] : "-");
    buf[buflen - 1] = 0;
}

/* mgrname= 的实参来自 ctl0 的栈缓冲，必须拷进静态存储（旧版直接存指针 ⇒
 * ctl0 返回后即悬垂引用）。 */
static char apk_mgr_name_storage[4][64];

long apk_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char cmd[64];
    char out[448];
    int n = 0;
    uint32_t uid = (uint32_t)current_uid();

    /* 准入 = 信任集（root ∪ 加载者 ∪ 管理器 ∪ allow=）。
     * 其余 uid 其实到不了这里（KP 门后命令 + 钩子已把它们判为排除），
     * 这里再兜一道；★旧版写成 uid!=0 会让管理器无法执行 status/sweep。 */
    if (!apk_trusted_uid(uid))
        return -EPERM;

    if (args) {
        while (args[n] && n < (int)sizeof(cmd) - 1) { cmd[n] = args[n]; n++; }
    }
    cmd[n] = 0;

    if (n > 0) {
        if (apk_str_prefix(cmd, "sweep")) {
            apk_need_refine = 1;            /* 允许重新修正（例如新装了管理器） */
            apk_refine("ctl0");
        } else if (apk_str_prefix(cmd, "allow=")) {
            uint32_t a = apk_atou(cmd + 6);
            int i, dup = 0;
            for (i = 0; i < apk_allow_cnt; i++)
                if (apk_allow_uids[i] == a) dup = 1;
            if (a && !dup && apk_allow_cnt < APK_ALLOW_MAX)
                apk_allow_uids[apk_allow_cnt++] = a;
            apk_excl(a, 0);                 /* 降级模式同样生效 */
        } else if (apk_str_prefix(cmd, "deny=")) {
            apk_excl((uint32_t)apk_atou(cmd + 5), 1);
        } else if (apk_str_prefix(cmd, "mgrname=")) {
            int i;
            const char *src = cmd + 8;
            /* 轮转：新名字进 [0]，其余后移 */
            for (i = 3; i > 0; i--) {
                int k;
                for (k = 0; k < 63; k++) {
                    apk_mgr_name_storage[i][k] = apk_mgr_name_storage[i - 1][k];
                    if (!apk_mgr_name_storage[i - 1][k]) break;
                }
                apk_mgr_name_storage[i][63] = 0;
                apk_mgr_names[i] = apk_mgr_name_storage[i];
            }
            if (src[0]) {
                int k;
                for (k = 0; k < 63 && src[k]; k++)
                    apk_mgr_name_storage[0][k] = src[k];
                apk_mgr_name_storage[0][k] = 0;
                apk_mgr_names[0] = apk_mgr_name_storage[0];
            }
            apk_need_refine = 1;
            apk_refine("mgrname");
        }
    }

    apk_status_line(out, (int)sizeof(out));
    if (out_msg && outlen > 0 && apk_copy_to_user) {
        int len = 0;
        while (out[len] && len < outlen - 1) len++;
        if (len > 0)
            (void)apk_copy_to_user(out_msg, out, (unsigned long)(len + 1));
    }
    return 0;
}

KPM_CTL0(apk_ctl0);

/* ========================== 安装 / 卸载 ========================== */
static long apk_init(const char *args, const char *event, void *reserved)
{
    int err = -1;
    (void)args; (void)event; (void)reserved;

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
    apk_vmalloc = (void *(*)(unsigned long))kallsyms_lookup_name("vmalloc");
    apk_vfree = (void (*)(const void *))kallsyms_lookup_name("vfree");
    apk_filp_open = (void *(*)(const char *, int, int))kallsyms_lookup_name("filp_open");
    apk_kernel_read = (long (*)(void *, void *, unsigned long, loff_t *))
        kallsyms_lookup_name("kernel_read");
    apk_filp_close = (int (*)(void *, void *))kallsyms_lookup_name("filp_close");

    /* 加载者：修正完成前临时受信（管理器手动加载 ⇒ 立即可用，无手工步骤） */
    apk_loader_uid = (uint32_t)current_uid();

    /* ① 钩住 KP 的 get_ap_mod_exclude：按调用者当场判定，覆盖任何 uid
     *    （含 Android isolatedProcess 的 9xxxx、多用户 10xxxx、以及未来任何
     *    新 uid 段）。真机实测：纯区间枚举漏掉 uid>=20000，普通 app 用
     *    isolatedProcess 就能换到新 uid 读走真实 superkey。 */
    err = hook((void *)get_ap_mod_exclude, (void *)apk_get_excl_hook,
               (void **)&apk_orig_get_excl);
    if (err || !apk_orig_get_excl) {
        APK_LOG("init: hook FAILED err=%d (ptr=%llx) -> 降级区间排除\n",
                err, (unsigned long long)(unsigned long)apk_orig_get_excl);
        apk_orig_get_excl = 0;
        apk_hook_ok = 0;
        apk_sweep_range(1);
    } else {
        apk_hook_ok = 1;
        APK_LOG("init: hooked get_ap_mod_exclude ok (orig=%llx)\n",
                (unsigned long long)(unsigned long)apk_orig_get_excl);
    }

    /* ② 加载者若在特权域（root/init/CLI），立刻做一次精确修正：此时读得了
     *    packages.list，管理器身份当场确定、多用户区间一并处理，且"不是管理器
     *    的加载者"会被立刻收回临时信任。若加载者是管理器（untrusted_app 域），
     *    文件读会被 SELinux 拒 ⇒ 保持临时信任 + 区间兜底，等 root 域的一次
     *    supercall（任何 root 下的 KP 命令都会触发）自动完成修正。 */
    if (apk_loader_uid < APK_AID_APP_START)
        apk_refine("init-privileged");

    APK_LOG("init v3.2.0 done loader=%u hook=%d swept=%d mgr=%u need_refine=%d\n",
            (unsigned)apk_loader_uid, apk_hook_ok, apk_swept,
            (unsigned)apk_mgr_uid, apk_need_refine);
    return 0;
}

static long apk_exit(void *reserved)
{
    (void)reserved;
    /* 顺序重要：① 先摘钩子（否则下面 unexclude 会被自己的钩子拦住判定）
     *           ② 再恢复 kstorage（降级模式才写过） */
    if (apk_hook_ok) {
        unhook((void *)get_ap_mod_exclude);
        apk_hook_ok = 0;
        apk_orig_get_excl = 0;
    }
    if (apk_swept)
        apk_sweep_range(0);
    if (apk_mgr_uid)
        apk_excl(apk_mgr_uid, 0);
    if (apk_pkgl) {
        if (apk_vfree) apk_vfree(apk_pkgl);
        apk_pkgl = 0;
    }
    APK_LOG("exit done\n");
    return 0;
}

KPM_INIT(apk_init);
KPM_EXIT(apk_exit);
/*
               ............................ ............. :................................         
             ............................ :. ............ -.................................        
            ............. ................=.............. =: ................. ...............      
           ............. ............... == ............. =- ................. ................     
          ............. ............... :+- ............. -+................... ................    
         .............. ................==- ............. -+: ................. .................   
        .............. ............... -==: ............. -+=.................. .................   
        .... ......... ................==+: ............. ===: ................ .................   
       ..... ......... .............. :+=+: ............. -*#= ................ .................   
       ..... ........ ............... -+#+- ............. -%@@= ............... .................   
      ...... ........ ................=*@*- ............. :@@@@: .............. .................   
      ..... ......... ................=%@@+. ............. %@@@%.   ........... .......... ......   
      ..... .......... ...            +@@@%+. ...           #@@@#==:..      .............. ......   
     ...... ........ -= ..:-=+*######%@@@@@@#+..::--:::-==+*%@@@@@@@@@%#*+=-:.  .......... ......   
     ...... ........ :@%%@@@@@%%##*@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@%%%@@@@@@@@%#=.......... ......   
    ....... ........ -@%#*+=-:.   ...+@@@@@@@@@@@@@@@@@@@@@@@@#*#*******#%%@@@@@.......... .......  
    ....... ........ -+-:.    .:::---.*@@@@@@@@@@@@@@@@@@@@@@@+.       .:--=+*#%: ........ .......  
    ....... .......      .:--========-*@@@@@@@@@@@@@@@@@@@@@@@@==--:::..     ..-:......... .......  
    ....... .....    -=-=============:*@@@@@@@@@@@@@@@@@@@@@@@@:==========--:.-.   ....... .......  
    .............  . ##:=============:#@@@@@@@@@@@@@@@@@@@@@@@#:============-=@@.  ....... .......  
    ...... ......... ##:=============:%@@@@@@@@@@@@@@@@@@@@@@@#:============-=@%.......... .......  
    ...... ......... #@:============--@@@@@@@@@@@@@@@@@@@@@@@@#:============-=@% ......... ......   
    ...... ......... %@*:===========-=@@@@@@@@@@@@@@@@@@@@@@@@#:============-=@% ......... ......   
    ...... ..........%@@+---======---#@@@@@@@@@@@@@@@@@@@@@@@@@=-===========:=@# ......... ......   
    ...... ..........@@@@#+========#@@@@@@@@@@@@@@@@@@@@@@@@@@@%=-----====--=@@# ......... ......   
    ...... ........ :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%**=+==-=+*@@@# ......... ......   
     ..... ........ :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@# ......... ......   
     ..... ........ -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+ ......... ......   
     ..... ........ =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@= ......... ......   
     ..... ........ =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@- ......... ......   
     ..... ........ =@@@@@@@@@@@@@@@@@@@@@@@@@@@%###*%@@@@@@@@@@@@@@@@@@@@@@@@@= ......... ......   
      .... ........ :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+........... ......   
      .... .........  :=%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-   .......... ......   
       ... .........     :=#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*=.     .......... ......   
       ... .........         .:=*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#+=:         .......... .....    
       ... .........                ...:-=++##%%%%%%%%###**+++=-:.              .......... .....    
       ... .........                         =========---...                    .......... .....    
       ... .........                  .:-=::-+==========+=--=-:.                .......... .....    
       ... .........               .:-=++=:+===============.++==                .......... .....    
       ... .........                *+====--+============+.-==*#                .......... .....    
        .. .........                %@%*+==:-============::+*%@#                .......... ....     
        ............                #@@@@@%%*=+++++++++-=*%@@@@=                 ......... ....     
        ... ........   -+           #@@@@@@@@@####%@%#+#@@@@@@@:          .*.    ......... ....     
        ... ........  *@+           %@@@@@@@@@@@@#+:+%@@@@@@@@%           .@%:  .......... ...      
        ... ........ *@@-           %@@@@@@@@@@@@#: :%@@@@@@@@%           :@@@: .......... ...      
        ... ........ #@@:           %@@@@@@@@@@@@@@*@@@@@@@@@@#           :@@@@+ ......... ...      
         .. ........ #@@.           @@@@@@@@@@@@@@@@@@@@@@@@@@#           =@@@@@. . ..........      
         ... ......  *@@.          .@@@@@@@@@@@@@@@@@@@@@@@@@@*           *@@@@@=  ...... ....      
         ...... ...+=@@@.          .@@@@@@@@@@@@@@@@@@@@@@@@@@+           %@@@@@@%- ...   ...       
          ....... -@@@@@.          .@@@@@@@@@@@@@@@@@@@@@@@@@@*           %@@@@@@@@- ........       

          我也要被检测吗
          我已经力竭了，LONGZE你赢了挺厉害的，这个只能算勉强解决吧
          都给我去换成KSU或者其他原版AP或者其他分支不要设置密钥
          这破鉴权设计架构我真服了
*/
