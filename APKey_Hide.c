/*
 * APKey_Hide —— 让 KernelPatch 的 supercall 接口对非受信调用者不可观测
 *
 *   模块名 : APKey_Hide
 *   版  本 : 3.6.2
 *   作  者 : Lun.
 *   许  可 : MIT
 *   平  台 : Android arm64（KernelPatch / APatch / 派生分支之上）
 *
 * ==========================================================================
 * v3.5.0（时序修复 + TOFU 窗口硬预算：关掉"无限可敲的半开窗口"暴露面）
 * ==========================================================================
 * 1) 设置了包名 ⇒ 不再需要"信任第一条命令的 uid"：
 *    cfg 有效时钩子与 ctl0 的 TOFU 认领通道【整体停用】（见 apk_get_excl_hook /
 *    apk_ctl0 的 !apk_cfg_valid 判断）—— 信任唯一来源是"设置包名经
 *    packages.list 确认出的 uid"（apk_mgr_uids）。窗口仍短暂保留，只是它的作用
 *    变成"让管理器的钥匙鉴权触达 KP，等 root 侧修正确认包名后关闭"，不再
 *    把第一个命令者升级为受信任 app。
 * 2) 鉴权时序问题（检测并修复）：
 *    · 旧 apk_refine 只要文件读不到就烧一次预算（tries++），而早期 boot
 *      /data 未挂载 ⇒ init 阶段必然读不到 ⇒ 4 次预算全耗在注定失败上，
 *      数据就绪后【永远不会】再修正 —— 正是"时序"导致管理器丢失。改为：
 *      只有【真正扫描过一次 packages.list】才 tries++，读不到文件不计预算；
 *    · 扫了但没命中任何管理器（尚未安装）⇒ 保留 need_refine，等下次 root
 *      supercall 再扫（受预算约束），命中即永久关闭修正需求；
 *    · packages.list 缓存：pkg=/mgrname=/unclaim/sweep 会置脏标记，下次
 *      refine 在持锁窗口内丢弃旧快照重读（★不能在 ctl0 里直接 vfree ——
 *      与另一 CPU 正在持 apk_pkgl 扫描的 refine 构成 use-after-free）。
 * 3) "一直检测、不输出结果"的暴露面（用户点出的关键）：
 *    半开窗口若无限期存在，本身就是一个可被反复敲、永远敲不出结果却不关闭
 *    的常驻时序/行为差异 —— 检测方据此即可判定"这里有个在做鉴权门控的模块"。
 *    给窗口加硬预算 APK_WINDOW_MAX：每放行一次应用段调用触达 KP 就计一次数，
 *    错误钥匙的反复探测每次都消耗预算，超预算 ⇒ 本 boot 内永久关窗，行为
 *    塌回与"已确认/已认领"完全一致的原生排除语义，暴露面随探测自毁。
 *    root 域 refine 与 ctl0（root 永不过滤）不受关窗影响，仍可自救。
 * 4) 内置管理器包名表精简为 folk/aster/apatch 三项（去掉 com.example.apatch）。
 *
 * ==========================================================================
 * v3.4.0（嵌入参数设置包名：替代内置信任表）
 * ==========================================================================
 * 嵌入 boot 时 kptools/APatch 的"设置事件和参数"会把参数串经 load_module 的
 * args 一路传进 KPM_INIT（未显式指定事件的 KPM 默认在 pre-kernel-init 加载，
 * 见 preset.h EXTRA_EVENT_KPM_DEFAULT）。v3.4 解析这串参数：
 *   · 接受 `pkg=<名>` / `mgr=<名>` 或裸 `<名>`（须是合法 Android 包名：
 *     [A-Za-z0-9._-]、含 '.'、长度 3~63）；取第一个有效者存进 apk_cfg_pkg；
 *   · 设置有效 ⇒ apk_name_is_mgr()【替代】内置表（me.yuki.folk / me.yuki.aster
 *     / me.bmax.apatch 全部不再使用），特权域修正只按当前设置的包名确认管理器，
 *     TOFU 窗口随之提前关闭；未设置/无效 ⇒ 维持 v3.3 内置表行为；
 *   · ctl0 新增 `pkg=<名>` 运行时改写、`pkg=`（空）清除回落内置表；
 *     改包名会清掉旧确认并重置修正预算（apk_refine_tries 提为文件级，
 *     pkg=/mgrname=/unclaim/sweep 均重置），避免预算耗尽后新包名无法确认。
 * 信任优先级：设置包名 > 内置表；两者只决定"名字校验"认谁，allow= / 加载者
 * 临时信任 / root / TOFU 认领通道维持 v3.3 语义不变。
 *
 * ==========================================================================
 * v3.3.0（嵌入模式 TOFU 认领：修"意外嵌入 boot 后重启导致管理器丢失"）
 * ==========================================================================
 * 模块嵌进 boot 后每次开机都由 KP 自己在 pre-kernel-init 事件里加载
 * （init 的 event != "load-file"），此时加载者是 uid 0，"加载者临时信任"
 * 对应用毫无意义；packages.list 修正又要等一次 root supercall 才触发 ——
 * 只要那个 root 调用不来，管理器 app 就被自己的钩子锁在门外（"管理器丢失"）。
 *
 * v3.3 在嵌入模式下加一条 TOFU（trust-on-first-use）认领通道：
 *   · 未认领、且名字修正还没确认过管理器时，钩子放行应用段 uid
 *     （[10000,90000)，isolated 9xxxx / 多用户派生段 / system·adb 段不放），
 *     让它们触达 KP 原生鉴权（钥匙正确或 KP 的包名+签名管理器校验）；
 *   · 认领点 = ctl0：KP 的 SUPERCALL_KPM_CONTROL 在 is_authed 闸门之后
 *     （supercall.c 的 `if (!is_authed) return -EPERM;`）⇒ 第一个能操作
 *     本模块的 app uid 必然已经"正确发送过命令"，当场记为 claimed_uid，
 *     成为后续受信任的 app，窗口随即关闭（其余 uid 恢复严格排除）；
 *   · 另一条关闭路径：root 域一次 supercall 触发修正，按 packages.list
 *     确认内置管理器包名（me.yuki.folk / me.yuki.aster / me.bmax.apatch，
 *     本轮已把 aster 加进内置表），mgr_cnt>0 即关窗；
 *   · ctl0 新增 unclaim（无参数）可清空认领与修正结果、重开窗口，供
 *     换管理器/误认领时自救（root 或已认领者执行）。
 *   · 降级模式（钩子装不上）+嵌入：区间排除跳过纯应用段 [10000,20000)，
 *     保住管理器经 KP 原生鉴权触达 ctl0 自救的通道；system/adb 与 isolated
 *     段照排。
 * 代价（诚实）：未认领的窗口内，应用段 uid 能触达 KP 原生鉴权路径，返回
 * 语义与"只装了 KP 没装本模块"一致 —— 不泄露 key（钥匙错一律原生
 * ENOENT），但"KP 存在性"在该窗口内对 app 可探测；且"第一个鉴权成功的
 * app 即被永久信任"意味着任何知道密钥的第三方 app 抢先发一条 ctl0 命令
 * 也能认领 —— 这与 KP 本身的威胁模型相同（知道密钥 ⇒ 完全控制），本模块
 * 在嵌入场景下不再额外收窄这一条。非嵌入（load-file）路径行为与 v3.2 一致。
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
KPM_VERSION("3.6.2");
KPM_LICENSE("MIT");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("不建议嵌入，嵌入记得设置管理器正确包名；Embedding is not recommended, and if you do embed, remember to set the manager with the correct package name;https://github.com/Lun-OS/APKey_Hide_KPM");

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
/* ★v3.6：su 白名单判定。与上面两个符号同在 sucompat.c 并被 KP_EXPORT_SYMBOL
 * （sucompat.c:70 / :345 / :354）——本模块已依赖后两者 ⇒ 引用它【不新增任何
 * 加载失败风险】。用途见 apk_get_excl_hook 的"语义等价兜底"。 */
extern int  is_su_allow_uid(uid_t uid);
/* ★v3.6：is_trusted_manager_uid_android —— KP 用【内置包名 + APK 签名摘要】判定
 * 的受信管理器（userd.c:75-95，导出点 userd.c:1079，确证有 KP_EXPORT_SYMBOL）
 * ⇒ 走 KP 导出表可解析，不会让模块加载失败。签名门不可伪造。
 * 把它接进信任集只有一个效果：真管理器永远可用。这不是"多开一个口子"，而是
 * 消除一种暴露面——管理器被我们自己误杀，"功能缺失"本身就是可观测的痕迹。
 * KP 的 before() 本来就会调它（supercall.c:406），我们再调一次不新增可观测面。
 *
 * ★v3.6 修正（上一版把钩子挂错了函数，属于真 bug，此处留档事实）：
 * 我原先钩的是 KP_EXPORT_SYMBOL 的 refresh_trusted_manager_uid（userd.c:1042），
 * 但把全树调用点查干净后确认：**它内部一次都没被调用**，只有
 *   · userd.h:14 的声明
 *   · userd.c:1068 的导出宏
 * 两处出现。KP 真正在每个触发点调用的，是【未导出】的
 * refresh_trusted_manager_state（userd.c:1064），调用点共 4 处：
 *   · userd.c:1357   on_first_app_process()   ← 首个 app_process 被 exec 之前
 *   · common/user_event.c:25  uid_listener/package-list-updated
 *   · common/supercmd.c:465   reload-cfg
 *   · userd.c:1634            内部 use_tmp=1 路径
 * ⇒ 挂在 refresh_trusted_manager_uid 上是彻底的死代码。
 * 改法：该函数未导出 ⇒ 用 kallsyms_lookup_name 尽力解析其地址；解析到就
 * hook_wrap，解析不到就【安全降级】（不挂，其余功能不受影响，见 init 第 ③ 步）。
 *
 * ★非 Android 的 KP 分支不导出 is_trusted_manager_uid_android ⇒ 直接 extern 会让
 * 模块加载期报 unknown symbol 而【不加载】（嵌入场景 = 保护静默消失）。这类分支用
 * -DAPK_NO_KP_USERD 关闭此处 userd.c 派生能力，其余功能不受影响。
 * 注：refresh_trusted_manager_state 走 kallsyms 动态解析，本就没有链接期符号依赖，
 * 因此不受该开关影响（解析失败只会降级，不会让模块不加载）。 */
#ifndef APK_NO_KP_USERD
extern int  is_trusted_manager_uid_android(uid_t uid);
#endif

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
/* ★v3.6：KP refresh 入口（refresh_trusted_manager_state）的 after 钩子状态与地址。
 * 两个变量都【无条件定义】：-DAPK_NO_KP_USERD 下只是永远为 0（不装钩子），
 * status 行/init 判据/ctl0 pkg= 判据都无需再加 #ifdef。 */
static int      apk_refresh_hooked;
/* 未导出 ⇒ 只能 kallsyms 动态解析；0=未解析到（此时不装钩子，功能降级）。
 * __attribute__((unused))：-DAPK_NO_KP_USERD 下这个变量只在 status 行/日志里被
 * 读到，编译器在某些配置下会判"未使用"，显式标注以保持 -Wall -Wextra 零告警。 */
static void    *apk_refresh_fn __attribute__((unused));
static uint32_t apk_mgr_uid;               /* 已确认的管理器 uid（0=未知） */
static int      apk_need_refine = 1;       /* 待特权域做一次精确修正 */
/* ★v3.6.2：【诊断用】apk_refine 至少成功读到过一次 packages.list（不管有没有
 * 匹配到管理器）。它把"文件读到了但名字没匹配上"和"文件根本还没就绪（/data 未
 * 挂载）"区分开——这正是判定上述时序风险时唯一需要看的一位。status 行 refok=。 */
static int      apk_refine_read_ok;
static uint32_t apk_mgr_uids[4];
static int      apk_mgr_cnt;
static uint32_t apk_allow_uids[APK_ALLOW_MAX];   /* ctl0 allow= 逃生口 */
static int      apk_allow_cnt;
static int      apk_embedded;              /* 嵌入模式：init 的 event != "load-file" */
static uint32_t apk_claimed_uid;           /* TOFU 认领的应用 uid（0=未认领） */
/* ★v3.4：嵌入（pre-kernel-init）参数里设置的信任包名。有效则【替代】内置表 */
static char     apk_cfg_pkg[64];
static int      apk_cfg_valid;
/* ★v3.5：TOFU 窗口硬预算——窗口内每放行一次应用段调用触达 KP 鉴权计一次数，
 * 超限即永久关窗（防"探测器反复打不开结果的窗口"成为常驻暴露面）。
 * ★v3.6：cfg（手动包名）模式的预算独立且大幅收紧——cfg 下窗口只是"refine
 * 确认前的临时桥"（管理器持钥匙经窗口完成 su/root，root 侧 supercall 触发
 * refine 后永久关窗；v3.6 起 KP 的 refresh 钩子还会在开机早期主动关它），
 * 不承担认领职责；窗口期是【非 root 检测器唯一还能触及的活面】（被放行 uid
 * 可触发懒页探针、可统计 pass/deny 差分），所以预算越小越好。
 * TOFU 无配置模式保留大预算（要靠它撑到第一个鉴权者出现）。
 *
 * ★v3.6【语义等价事实】（已逐条对照 KP 源码，非推测）：
 *   1) hook.c:357/364 —— fargs.skip_origin 默认 0，before() 不置位则
 *      _transitN 会调用 origin_func()（= 被钩函数的原始体）。
 *   2) supercall.c:393 —— `if (get_ap_mod_exclude(uid)) return;` 是【早返回且
 *      不置 skip_origin】⇒ 落到原始 sys_call_table[45]。
 *   3) scdefs.h:20-21 —— `__NR_supercall` 就是 45，而 45 在 arm64 上是
 *      truncate；KP 从不改写 sys_call_table[45]，只对它做 fp hook。
 *   ⇒ 本模块把非受信 uid 判为"已排除"（return 1）时，调用者拿到的就是
 *      【原生 truncate 的返回】——与"KP 存在但没有本模块、且调用者拿不出正确
 *      钥匙"时的返回逐位相同（那条路径同样因 !is_trusted_caller 早返回而落到
 *      truncate）。不读钥匙、不碰任何用户内存、无副作用，差分面为零。
 *   4) 模块内部计数（apk_n_deny/apk_n_pass/apk_window_*）全在模块私有数据段，
 *      非 root 不可见；release 构建 APK_LOG 编译为空。 */
#define APK_WINDOW_MAX      8192u
#define APK_WINDOW_MAX_CFG  256u
static volatile uint32_t apk_window_calls;
static volatile int      apk_window_closed;

/* ★v3.6：立即关窗（幂等）。窗口唯一的存在理由是"管理器 uid 尚未被确认之前，
 * 让它还能走到 KP 的原生鉴权"；一旦管理器 uid 已知（refine 按包名命中 / TOFU
 * 认领 / 加载者已在特权域确认），窗口就再无存在理由。窗口期是本模块唯一还能被
 * 【非 root 调用者】触及的活面（被放行的 uid 可触发惰性页探测、可统计 pass/deny
 * 差分），所以关得越早越好：不是"等预算烧完"，而是"一知道就关"。 */
static void apk_window_shut(void)
{
    if (!apk_window_closed) {
        apk_window_closed = 1;
        APK_LOG("window shut (calls=%u)\n", (unsigned)apk_window_calls);
    }
}

static volatile uint32_t apk_n_deny;       /* 被钩子判为排除的调用数 */
static volatile uint32_t apk_n_pass;       /* 被钩子放行的调用数 */

/* 已知管理器包名（内置知识，非用户配置；可用 ctl0 mgrname= 追加）
 * ★这三个包名对应本模块的信任目标：me.yuki.folk / me.yuki.aster / me.bmax.apatch */
static const char *apk_mgr_names[APK_MGR_NAME_MAX] = {
    "me.yuki.folk",          /* FolkPatch 管理器 */
    "me.yuki.aster",         /* Aster 管理器 */
    "me.bmax.apatch"       /* 原版 APatch 管理器 */

};

/* ★v3.4：Android 包名字符集校验（字母/数字/'.'/'_'/'-'，含至少一个 '.'，
 * 长度 [3,63]）。嵌入参数只有过这关才被当作"有效包名"。 */
static int apk_pkg_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static int apk_pkg_valid(const char *s)
{
    int n = 0, dot = 0;
    if (!s || !s[0]) return 0;
    while (s[n]) {
        if (!apk_pkg_char_ok(s[n])) return 0;
        if (s[n] == '.') dot = 1;
        if (++n > 63) return 0;
    }
    return dot && n >= 3;
}

/* 解析嵌入时 KP 传给 init 的 args（kptools/APatch 的"设置事件和参数"里的
 * 参数串）。token 形如 `pkg=NAME` / `mgr=NAME`，或裸 `NAME`（须自身是合法
 * 包名）。取第一个有效者写入 apk_cfg_pkg ⇒ 名字校验【替代】内置表。 */
static void apk_parse_init_args(const char *args)
{
    char tok[64];
    while (args && *args) {
        int n = 0, k;
        const char *v;
        while (*args && *args != ' ' && *args != '\t' && n < 63)
            tok[n++] = *args++;
        tok[n] = 0;
        while (*args == ' ' || *args == '\t') args++;
        if (!n) continue;
        v = tok;
        if ((tok[0] == 'p' || tok[0] == 'P') && (tok[1] == 'k' || tok[1] == 'K') &&
            (tok[2] == 'g' || tok[2] == 'G') && tok[3] == '=') {
            v = tok + 4;
        } else if ((tok[0] == 'm' || tok[0] == 'M') && (tok[1] == 'g' || tok[1] == 'G') &&
                   (tok[2] == 'r' || tok[2] == 'R') && tok[3] == '=') {
            v = tok + 4;
        }
        if (apk_pkg_valid(v)) {
            for (k = 0; v[k] && k < 63; k++) apk_cfg_pkg[k] = v[k];
            apk_cfg_pkg[k] = 0;
            apk_cfg_valid = 1;
            APK_LOG("cfg pkg override: %s\n", apk_cfg_pkg);
            return;
        }
    }
}

static int apk_name_is_mgr(const char *pkg)
{
    int i;
    /* ★v3.4：嵌入参数（或 ctl0 pkg=）给出过有效包名 ⇒ 不使用内置表，
     * 只认当前设置的这一个包名。 */
    if (apk_cfg_valid) {
        const char *a = apk_cfg_pkg;
        const char *b = pkg;
        while (*a && *a == *b) { a++; b++; }
        return (!*a && (!*b || *b == ' ' || *b == '\n')) ? 1 : 0;
    }
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
/* ★v3.5：缓存失效改为"脏标记"而不是直接 vfree——invalidate 可能在 ctl0（
 * 另一 CPU）被调用，正持有 apk_pkgl 做扫描的 refine 若被并发释放就是
 * use-after-free。置脏永远安全；真正的释放/重读只发生在 apk_load_pkglist
 * 内部（即 refine 持锁窗口里）。 */
static volatile int apk_pkgl_dirty;

static void apk_pkgl_invalidate(void)
{
    apk_pkgl_dirty = 1;
}

static int apk_load_pkglist(void)
{
    void *fp;
    loff_t pos = 0;
    long n;

    /* ★v3.5：有脏标记 ⇒ 丢弃旧快照重读 */
    if (apk_pkgl && apk_pkgl_dirty) {
        if (apk_vfree) apk_vfree(apk_pkgl);
        apk_pkgl = 0;
        apk_pkgl_len = 0;
        apk_pkgl_dirty = 0;
    }
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
 * 兜底"，正常路径（钩子成功）完全不写 kstorage。
 * ★v3.3 嵌入 + 降级：跳过纯应用段 [10000,20000)（管理器就住在这里）——没有
 * 钩子就没有"窗口"可控，但排除它会让管理器连 KP 原生鉴权都到不了、彻底丢失；
 * 保住"管理器能鉴权、能 ctl0 自救"优先。system/adb 段与 isolated 段照排。 */
static void apk_sweep_range(int exclude)
{
    if (apk_embedded && exclude) {
        apk_sweep_span(APK_AID_EXCL_START, APK_AID_APP_START, exclude);
    } else {
        apk_sweep_span(APK_AID_EXCL_START, APK_AID_EXCL_END, exclude);
    }
    apk_sweep_span(APK_AID_ISO_START, APK_AID_ISO_END, exclude);
    apk_swept = exclude;
    APK_LOG("sweep(deg) exclude=%d embedded=%d -> excl=%u skip=%u\n",
            exclude, apk_embedded, (unsigned)apk_n_excl, (unsigned)apk_n_skip);
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

/* 特权域（root）里跑的一次修正；★v3.5 时序修复：文件读不到（早期 boot，
 * /data 还没挂载 / packages.list 尚不存在）【不】烧预算——旧版会把 4 次预算
 * 全耗在 init 阶段的必然失败上，导致数据就绪后永远不再修正。
 * 扫描成功但没找到任何管理器（例如还没安装）⇒ 保留 need_refine，下次 root
 * 调用再扫（仍受预算限制），扫到即永久关闭修正需求。 */
static int apk_refine_tries;
static void apk_refine(const char *why)
{
    if (!apk_need_refine)
        return;
    if (apk_refine_tries >= APK_REFINE_MAX_TRY)
        return;
    /* 防重入：两个 CPU 同时命中 root supercall 时只让一个读文件 */
    if (apk_refining)
        return;
    apk_refining = 1;

    (void)why;                              /* release 版无日志，仅调试打印用 */
    if (!apk_load_pkglist()) {
        APK_LOG("refine(%s): no packages.list (data not ready?) -> 不烧预算\n", why);
        apk_refining = 0;
        return;
    }
    apk_refine_tries++;
    apk_refine_read_ok = 1;                 /* ★v3.6.2：文件确实读到了（诊断用） */
    APK_LOG("refine(%s#%d): scanning packages.list\n", why, apk_refine_tries);
    apk_each_pkg(apk_refine_cb, 0);
    if (apk_mgr_cnt) {
        apk_need_refine = 0;                /* 确认到管理器 ⇒ 修正完成 */
        /* ★v3.6【时序要点】管理器的"正确 uid"就是在这里第一次被拿到的
         * （按 packages.list 的 包名↔uid 映射）。既然已知，就【当场】关窗——
         * 之后唯一放行路径是 apk_trusted_uid 里的 apk_mgr_uids[]，其余 uid 全部
         * 塌回原生语义。刻意放在这里而不是等钩子下次自己判：判是懒的，一旦
         * 管理器确认后仍有并发的窗口调用在飞，懒判会多放行几拍。 */
        apk_window_shut();
    }
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

#ifndef APK_NO_KP_USERD
/* ★v3.6：KP refresh 入口的 after 回调。只做一件事：跑一次我们的精确修正。
 * 刻意【不碰 fargs】——不置 skip_origin、不改 ret、不改 local，KP 的原流程
 * 与返回值零影响（hook.c:368-372 的 after 循环只是回调，返回值取自 fargs.ret）。
 * 这里必然在特权域上下文（该函数本身就是 KP 成功读完 packages.list 后调的），
 * 所以 apk_load_pkglist 的 filp_open 会成功；真失败也无害（apk_refine 不烧预算）。 */
static void apk_refresh_after(hook_fargs0_t *args, void *udata)
{
    (void)args;
    (void)udata;
    apk_refine("kp-refresh");
}
#endif

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
    /* ★v3.3：嵌入模式 TOFU 认领的 app（第一个正确发送命令的调用者） */
    if (apk_claimed_uid && u == apk_claimed_uid)
        return 1;
    /* 加载者：仅在特权域修正完成前临时放行。
     * 修正后仍受信 ⇔ 它确实是被 packages.list 证实的管理器（在前一循环里）；
     * 否则（例如某个 app 抢先用公开钥匙加载）在此被重新拒绝。 */
    if (apk_loader_uid && u == apk_loader_uid && apk_need_refine)
        return 1;
#ifndef APK_NO_KP_USERD
    /* ★v3.6：KP 自己签名校验过的受信管理器（userd.c:75-95 的内置表 + APK 签名
     * 摘要比对，拿不到私钥就伪造不了）。接它进来的唯一目的是保证真管理器不被
     * 我们误杀——误杀 = 功能缺失 = 本身就是可观测痕迹。KP 的 before() 本来也
     * 会调它（supercall.c:406），这里多调一次不新增任何可观测面。 */
    if (is_trusted_manager_uid_android((uid_t)u))
        return 1;
#endif
    return 0;
}

/* ========================== 嵌入模式 TOFU（v3.3） ==========================
 * 认领点 = ctl0：KP 的 SUPERCALL_KPM_CONTROL 在 supercall() 的
 * `if (!is_authed) return -EPERM;` 闸门之后（supercall.c:347），而 is_authed
 * ⇔ 调用者的钥匙 auth_superkey 通过（或被 KP 自己的 包名+APK签名 校验认作
 * 受信管理器）。⇒ 第一个能走进 apk_ctl0 的应用 uid 就是"第一个正确发送命令
 * 的应用"，当场认领为后续受信任的 app。
 * ★刻意不在这里 hook KP 的判定函数：auth_superkey 未被 KP_EXPORT_SYMBOL，
 * symbol_lookup_name / kallsyms 都解析不到 ⇒ extern 引用会直接让整个模块
 * 加载失败（simplify_symbols 对未解析符号返回 -ENOENT）。
 * 未认领前的"窗口"里，应用段 uid 被放行触达 KP 原生鉴权：钥匙错的调用者被
 * KP 自己拒绝（返回语义与纯 KP 一致），钥匙对的第一个调用者到达 ctl0 即认领，
 * 窗口随即关闭。三个内置管理器包名（folk/aster/apatch）在特权域修正后按
 * packages.list 直接进信任集，与认领互不冲突。 */

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

    /* ★v3.3 嵌入模式的 TOFU 窗口：未认领且名字修正还没确认过管理器时，
     * 放行"应用段"uid（isolated 9xxxx、system/adb 段一律不放行），让它们能
     * 触达 KP 的原生鉴权；第一个鉴权成功并操作本模块（ctl0）的应用会被认领，
     * 或特权域修正按包名确认管理器后，窗口即关闭、恢复严格排除。
     * ★v3.5：
     *  · cfg 有效（手动设置过包名）⇒【不再 TOFU 认领"第一条命令的 uid"】：
     *    信任只来自"设置包名经 packages.list 确认的 uid"；但窗口本身保留
     *    （管理器 app 的钥匙鉴权/原生探测仍要触达 KP），由 root 侧修正确认
     *    或预算耗尽关闭；
     *  · 窗口带硬预算：放行次数超预算即永久关窗。拿错误钥匙
     *    反复探测的调用者每次都会消耗预算；预算耗尽 ⇒ 其看到的行为塌回
     *    "已确认/已认领"的原生排除语义，模块不再提供一个可以【无限期】
     *    敲的"半开窗口"（无限可敲 = 常驻时序/行为差异 = 暴露面，也正是
     *    探测方"一直检测不出结果却不关"要利用的形态）。关窗不影响自救：
     *    root 域 refine、ctl0 allow=/unclaim/pkg= 依旧可达（root 永不过滤）。
     * ★v3.6：预算只是【兜底】，不是关窗的主要手段。真正的手段是"一知道管理器
     *    uid 就立刻关窗"（apk_window_shut：refine 命中、TOFU 认领、init 时
     *    cfg 包名生效 三处都会主动关）。顺带修掉一个懒判的时序漏洞：窗口条件
     *    以前只由钩子在被调用的那一刻读状态，管理器确认后若仍有并发调用在飞，
     *    会多放行几拍；现在由确认方主动关，窗口在"确认瞬间"就没了。 */
    if (apk_embedded && !apk_claimed_uid && !apk_mgr_cnt &&
        !apk_window_closed &&
        u >= APK_AID_APP_START && u < APK_AID_ISO_START) {
        /* ★v3.6：预算按模式取——cfg（手动包名）下窗口只是"refine 确认前的临时桥"，
         * 收紧到 256；TOFU 无配置模式保留 8192（要靠它撑到第一个鉴权者）。 */
        uint32_t wmax = apk_cfg_valid ? APK_WINDOW_MAX_CFG : APK_WINDOW_MAX;
        if (++apk_window_calls > wmax) {
            APK_LOG("window budget exhausted (%u/%u cfg=%d)\n",
                    (unsigned)apk_window_calls, (unsigned)wmax, apk_cfg_valid);
            apk_window_shut();              /* 预算耗尽：本 boot 内永久关窗 */
        } else {
            apk_n_pass++;
            return 0;
        }
    }

    /* ★v3.6【语义等价兜底：su 白名单 uid 必须放行】
     * 事实（supercall.c:406-413）：KP 的 before() 对 su 白名单 uid 置
     * is_trusted_caller=1（is_authed 仍为 0）⇒ 它【不会】早返回，而是继续走
     * 命令分发：特权命令拿 -EPERM、未知命令拿 -ENOSYS、HELLO/TEST/BOOTLOG 正常。
     * su 白名单 uid 是【非 root 的普通应用 uid】，且不在本模块信任集里——若我们
     * 把它判为排除，它拿到的是原生 truncate 的返回，与"没有本模块"逐位不同，
     * 这正是必须消除的痕迹。放行后 KP 原生流程原样执行，返回逐位一致。
     * 安全性：is_authed 仍为 0，而 SUPERCALL_KPM_CONTROL 在
     * `if (!is_authed) return -EPERM;`（supercall.c:347）之后 ⇒ 它够不到本模块
     * 的 ctl0，不构成新口子；SKEY_GET/SKEY_SET 同样在门后，读不到钥匙。
     * 成本：只在"即将判 deny"这条路径上多一次 kstorage 查表——而 native KP 在
     * 同一流程的 supercall.c:409 本来就要做同样的查表，成本面貌反而更贴近原生。 */
    if (is_su_allow_uid(uid)) {
        apk_n_pass++;
        return 0;
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
                 "APKey_Hide v3.6.2 hook=%d refresh=%d swept=%d loader=%u mgr=%u "
                 "embedded=%d claimed=%u cfgpkg=%s win=%u/%d need_refine=%d refok=%d "
                 "allow=%d deny=%u pass=%u "
                 "n(excl=%u unexcl=%u skip=%u) names=%s,%s,%s,%s",
                 apk_hook_ok, apk_refresh_hooked, apk_swept, (unsigned)apk_loader_uid,
                 (unsigned)apk_mgr_uid, apk_embedded,
                 (unsigned)apk_claimed_uid,
                 apk_cfg_valid ? apk_cfg_pkg : "-",
                 (unsigned)apk_window_calls, apk_window_closed,
                 apk_need_refine, apk_refine_read_ok, apk_allow_cnt,
                 (unsigned)apk_n_deny, (unsigned)apk_n_pass,
                 (unsigned)apk_n_excl, (unsigned)apk_n_unexcl,
                 (unsigned)apk_n_skip,
                 apk_mgr_names[0] ? apk_mgr_names[0] : "-",
                 apk_mgr_names[1] ? apk_mgr_names[1] : "-",
                 apk_mgr_names[2] ? apk_mgr_names[2] : "-",
                 apk_mgr_names[3] ? apk_mgr_names[3] : "-");
    buf[buflen - 1] = 0;
}

/* mgrname= 的实参来自 ctl0 的栈缓冲，必须拷进静态存储（旧版直接存指针 ⇒
 * ctl0 返回后即悬垂引用）。 */
static char apk_mgr_name_storage[4][64];

long apk_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char cmd[64];
    /* ★v3.6.2：448 不够——最坏情况（4 个包名各 63 字符 + 各计数取满 uint32）
     * 实测需 650 字节，旧值会把尾部 names= 段静默截掉。而 status 正是排查
     * "refine 到底有没有成功读到 packages.list"这类时序问题要看的输出，不能截。
     * 768 留足余量；snprintf 本身有界，apk_status_line 末尾另有 buf[buflen-1]=0 兜底。 */
    char out[768];
    int n = 0;
    uint32_t uid = (uint32_t)current_uid();

    /* ★v3.3 嵌入模式 TOFU：SUPERCALL_KPM_CONTROL 在 KP 的 is_authed 闸门之后
     * （supercall.c：钥匙正确或被 KP 认作受信管理器才会走到 ctl0）⇒ 能到达这里
     * 的 app 就是"第一个正确发送命令的应用"，当场认领为后续受信任的 app。
     * 认领条件与钩子的窗口条件一致（未认领且名字修正未确认过管理器）；
     * ★v3.5：cfg 有效（手动设置过包名）⇒ 信任只按包名确认，不做 TOFU 认领。
     * 认领后（或非嵌入路径）准入仍走信任集。 */
    if (apk_embedded && !apk_cfg_valid && !apk_claimed_uid && !apk_mgr_cnt &&
        uid >= APK_AID_APP_START && uid < APK_AID_ISO_START) {
        apk_claimed_uid = uid;
        /* ★v3.6：认领即"管理器 uid 已知" ⇒ 当场关窗（与 refine 命中同一语义）。
         * 之后只有 apk_claimed_uid 这一个 uid 经 apk_trusted_uid 放行，
         * 其余 uid 全部拦。这是 TOFU 模式下窗口的终结时刻。 */
        apk_window_shut();
        APK_LOG("claim via ctl0 uid=%u\n", (unsigned)uid);
    } else if (!apk_trusted_uid(uid)) {
        /* 其余 uid 其实到不了这里（KP 门后命令 + 钩子已把它们判为排除），
         * 这里再兜一道；★旧版写成 uid!=0 会让管理器无法执行 status/sweep。
         *
         * ★v3.6【返回值必须是 -ENOENT，不能是 -EPERM】——事实依据：
         * module.c:548-550，KP 的 module_control0 在 find_module(name) 返回
         * NULL 时 rc = -ENOENT。而"没有本模块"的语义就是这个名字查不到
         * ⇒ 原生返回必然是 -ENOENT。旧版这里返回 -EPERM，在【降级模式】
         * （get_ap_mod_exclude 钩子装不上）下会真的被"持钥匙的非受信调用者"
         * 摸到：拿到 -EPERM 而不是 -ENOENT，等于自报"这台机器上有个模块在
         * 藏自己"。改成 -ENOENT 后与"模块不存在"逐位一致。
         * 注：钩子正常的路径下非受信 uid 根本到不了这一行（早在前一层被判
         * 排除 → KP before() 早返回 → 落到 truncate），这里是降级模式的兜底。 */
        return -ENOENT;
    }

    if (args) {
        while (args[n] && n < (int)sizeof(cmd) - 1) { cmd[n] = args[n]; n++; }
    }
    cmd[n] = 0;

    if (n > 0) {
        if (apk_str_prefix(cmd, "sweep")) {
            apk_need_refine = 1;            /* 允许重新修正（例如新装了管理器） */
            apk_refine_tries = 0;           /* ★v3.4：显式动作重置修正预算 */
            apk_pkgl_invalidate();          /* ★v3.5：重扫前丢弃旧快照 */
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
        } else if (apk_str_prefix(cmd, "pkg=")) {
            /* ★v3.4：运行时覆盖/清除"设置的包名"。pkg=<名> 有效则替代内置表；
             * pkg=（空）清除设置、回落内置表。改动后清掉旧确认并请求重扫。 */
            const char *src = cmd + 4;
            int k;
            if (apk_pkg_valid(src)) {
                for (k = 0; src[k] && k < 63; k++) apk_cfg_pkg[k] = src[k];
                apk_cfg_pkg[k] = 0;
                apk_cfg_valid = 1;
            } else {
                apk_cfg_pkg[0] = 0;
                apk_cfg_valid = 0;
            }
            apk_mgr_cnt = 0;
            apk_mgr_uid = 0;
            apk_need_refine = 1;
            apk_refine_tries = 0;           /* ★v3.4：显式改包名重置修正预算 */
            apk_pkgl_invalidate();          /* ★v3.5：新包名 ⇒ 旧快照作废重读 */
            /* ★v3.6.2：状态机不变式 = "窗口开着 ⟺ 管理器 uid 未知"。
             * 上面刚把 mgr_cnt 清 0（uid 又变未知了）⇒ 窗口必须重新打开，
             * 否则若新包名一时匹配不上，管理器会被锁在门外且无法自救。
             * 能执行本命令者已在信任集内，不构成新的暴露面。 */
            apk_window_calls = 0;
            apk_window_closed = 0;
            if (apk_loader_uid < APK_AID_APP_START)
                apk_refine("pkg");          /* 命中则内部立刻关窗 */
        } else if (apk_str_prefix(cmd, "unclaim")) {
            /* ★v3.3：清空 TOFU 认领（换机/重装后重新认领）。
             * 顺带清掉已确认管理器、重开窗口，并请求一次特权域修正。
             * ★v3.5：窗口预算/关窗标记一并重置（能执行此命令者已在信任集内，
             * 不构成新的重开面）。 */
            apk_claimed_uid = 0;
            apk_mgr_cnt = 0;
            apk_mgr_uid = 0;
            apk_window_calls = 0;
            apk_window_closed = 0;
            apk_need_refine = 1;
            apk_refine_tries = 0;           /* ★v3.4：重置修正预算 */
            apk_pkgl_invalidate();          /* ★v3.5：重扫前丢弃旧快照 */
            if (apk_loader_uid < APK_AID_APP_START)
                apk_refine("unclaim");
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
            apk_refine_tries = 0;           /* ★v3.4：重置修正预算 */
            apk_pkgl_invalidate();          /* ★v3.5：名字表变了 ⇒ 旧快照作废 */
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
    (void)reserved;

    /* ★v3.3：判别嵌入模式。手动加载走 SUPERCALL_KPM_LOAD → load_module_path
     * 传 event="load-file"；嵌进 boot 由 KP 在 pre-kernel-init/post-kernel-init
     * 等事件里自加载 ⇒ event != "load-file"。嵌入模式才开 TOFU 认领通道。
     * ★不依赖 strcmp：模块未定义符号只走 KP 导出表解析，引一个不存在的
     * libc 会让整个模块加载失败（simplify_symbols 返回 -ENOENT）。 */
    apk_embedded = !(event && event[0] == 'l' && event[1] == 'o' &&
                     event[2] == 'a' && event[3] == 'd' && event[4] == '-' &&
                     event[5] == 'f' && event[6] == 'i' && event[7] == 'l' &&
                     event[8] == 'e' && !event[9]);
    apk_claimed_uid = 0;
    apk_cfg_pkg[0] = 0;
    apk_cfg_valid = 0;

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

    /* ★v3.4：嵌入加载时（未显式指定事件的 KPM 默认在 pre-kernel-init 加载，
     * EXTRA_EVENT_KPM_DEFAULT=pre-kernel-init），KP 会把"设置事件和参数"里
     * 的参数串原样传进 args。解析出有效包名 ⇒ 名字校验只用这一个包名，
     * 不再使用内置表；参数缺失/无效 ⇒ 维持内置表。
     * （放在符号解析之后：APK_LOG 依赖 apk_printk。） */
    if (apk_embedded)
        apk_parse_init_args(args);

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

#ifndef APK_NO_KP_USERD
    /* ③ ★v3.6：只挂 after 的 refresh 钩子。目标必须是 KP 实际调用的那一个函数
     *    ——refresh_trusted_manager_state（userd.c:1064，共 4 个内部调用点）。
     *    它【未导出】，所以走 kallsyms 动态解析；解析不到就不挂（安全降级：
     *    我们仍然有 uid0 supercall 这条路——APatch 守护进程上报
     *    uid_listener/package-list-updated 时是 uid 0，其 supercall 必然进入
     *    我们的钩子并触发 apk_refine("hook-uid0")，那条路在特权域、能读文件）。
     *    挂上之后：KP 每次刷新受信管理器，我们在同一特权域上下文补跑一次修正，
     *    于是"管理器 uid 已知"这一刻发生在开机极早期（首个 app_process exec 前），
     *    窗口随即关闭。
     *    after-only：before 传 NULL（_transit0 里 `if (func)` 有判空），
     *    回调不碰 fargs ⇒ KP 返回值与原流程零影响。 */
    apk_refresh_fn = (void *)kallsyms_lookup_name("refresh_trusted_manager_state");
    if (apk_refresh_fn &&
        !hook_wrap(apk_refresh_fn, 0, (void *)0, (void *)apk_refresh_after, (void *)0))
        apk_refresh_hooked = 1;
    APK_LOG("init: refresh fn=%llx hooked=%d\n",
            (unsigned long long)(unsigned long)apk_refresh_fn, apk_refresh_hooked);
#endif

    /* ④ ★v3.6.2【关窗判据修正 —— 只按"管理器 uid 已知"关，不再按 cfg 关】
     *    窗口唯一的正当理由是"管理器 uid 还没被确认前，让它还能走到 KP 原生
     *    鉴权"。所以语义上唯一充分的关窗条件是 apk_mgr_cnt > 0（管理器 uid 已由
     *    packages.list 的 包名↔uid 映射拿到）。据此：
     *      · init 时若已确认（典型 = 手动/临时加载 + 加载者在特权域，第 ② 步的
     *        refine 当场命中）⇒ 关窗，之后只有 apk_mgr_uids 放行，其余全拦；
     *      · 未确认 ⇒ 【保持开着】，等 apk_refine 第一次成功确认时立刻关
     *        （apk_window_shut 就在那里调用）。窗口长度 = init → 首次成功 refine，
     *        通常就是开机那次 package-list-updated / uid0 事件，仍然极短。
     *
     *    ★为什么删掉了"apk_cfg_valid 就关窗"（v3.6.1 的 ②，是错的）：
     *      cfg 只说明"包名设过"，不说明"uid 已知"。反例（成立）：
     *      第一次 uid0 supercall 发生在 /data 挂载之前 ⇒ apk_load_pkglist 失败
     *      ⇒ 不烧预算、apk_mgr_cnt 仍为 0、apk_need_refine 仍为 1；此时若窗口
     *      已在 init 关掉，而之后又【没有】第二次 uid0 supercall / 事件上报，
     *      apk_refine 就永远不会再被触发 ⇒ 真管理器被【永久】拒绝，且 ctl0 在
     *      KP 的 is_authed 门之后，管理器自己连自救都做不到。
     *      这是在赌"你的分支一定会调用 refresh_trusted_manager_state"——
     *      而 4 个调用点里只要分支裁剪过（例如只剩可能早于 /data 的 reload-cfg），
     *      这个赌注就输。用可靠性换一点窗口压缩，不划算。
     *
     *    ★现在的时序保证：关窗依赖的是"refine 成功"这个【已发生的事实】，
     *      不再依赖"未来一定会发生"的假设。任何一次 uid0 supercall（含守护进程
     *      上报事件时的那次）都会在 /data 就绪后把 uid 学出来并当场关窗；
     *      若某分支从不产生 uid0 supercall，则窗口一直保留（上限由预算兜底：
     *      cfg 模式 APK_WINDOW_MAX_CFG=256），管理器至少不会失联。 */
    if (apk_mgr_cnt)
        apk_window_shut();                  /* 已确认 ⇒ 关窗 */
    APK_LOG("init: window closed=%d cfg=%d refresh=%d mgr=%d need_refine=%d\n",
            apk_window_closed, apk_cfg_valid, apk_refresh_hooked, apk_mgr_cnt,
            apk_need_refine);

    APK_LOG("init v3.6.2 done loader=%u hook=%d swept=%d mgr=%u embedded=%d "
            "need_refine=%d cfg=%d winclosed=%d\n",
            (unsigned)apk_loader_uid, apk_hook_ok, apk_swept,
            (unsigned)apk_mgr_uid, apk_embedded, apk_need_refine, apk_cfg_valid,
            apk_window_closed);
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
#ifndef APK_NO_KP_USERD
    if (apk_refresh_hooked && apk_refresh_fn) {
        hook_unwrap(apk_refresh_fn, (void *)0, (void *)apk_refresh_after);
        apk_refresh_hooked = 0;
    }
#endif
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

          我也要被检测吗,我已经力竭了，
          这破鉴权设计架构我真服了
*/
