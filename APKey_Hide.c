/*
 * APKey_Hide —— APatch / KernelPatch supercall 鉴权泄漏防护
 *
 *   模块名 : APKey_Hide
 *   作  者 : Lun.
 *   许  可 : MIT
 *   平  台 : Android arm64（KernelPatch / APatch 之上）
 *
 * ---------------------------------------------------------------------------
 * v2.1：v2.0 链式架构 + 页侧信道守卫（G2）。两条检测通道同时关闭。
 * ---------------------------------------------------------------------------
 *
 * 【检测器的两条通道与对应防线】
 *
 *  A. 返回值通道（主判据）：KP 的信息类命令（HELLO/VER/KLOG…）在鉴权门
 *     （supercall.c `if (!is_authed) return -EPERM`）之前，任意 uid 可拿
 *     kpver/magic。⇒ nr45 链上观察 KP 裁决（skip_origin/ret），未受信者
 *     净化为原生 truncate 语义。
 *
 *  B. 内存页通道（辅助判据）：KP before() 判信任**之前**就
 *     compat_strncpy_from_user(key, x0) —— 检测器用懒分配页（VMA 有、
 *     PTE 无）当 x0，调用后 mincore 查页是否被换入；换入 ⇒ 只有 KP 读过。
 *     本模块 nr45 钩子跑在 KP（链槽 0）之后，页已被读 ⇒ 必须钩更底层：
 *     compat_strncpy_from_user 本身（KP 全局唯一用户字符串读取原语）。
 *
 * 【G2 为什么逐字节等价、不破坏兼容】
 *   懒页内容恒为全 0：内核真读它 = 空串 = strncpy_from_user 返回 0，
 *   KP 走 `if (len <= 0) return;` 正常失败分支。G2 对「未受信 uid + 页
 *   确信缺失」直接返回 0 —— 返回值与控制流完全一致，唯一差别是页没有被
 *   换入（这正是要隐藏的副作用）。合法客户端的密钥串必须写入过页才可能
 *   鉴权 ⇒ 页必然 present ⇒ 原样放行，零干扰。
 *   KP 判定未受信 ⇒ skip_origin=0 ⇒ 原生 truncate 照跑：
 *     x1<0 → 干净内核不读 x0、返回 -EINVAL；G2 短路后同样一字不读 ⇒ 0→0。
 *     x1>=0 → 原生 getname(x0) 本来就会把页换入 ⇒ 有→有，无差异。
 *
 * 【误判防线（v0.5.3 事故教训，缺一不可）】
 *   1) 页表研判经 oracle 武装（walk_ver）："调用者 PC 页必然 present"，
 *      遍历说它不可用 ⇒ 标定错了 ⇒ 永久 fail-open，G2 永不拦截；
 *   2) apk_user_page_absent：任何不确定一律视为"可用"（放行读取）；
 *   3) uid ∈ 学习集∪白名单（root/管理器/已鉴权者）永不受影响；
 *   4) 安装/标定任一失败 ⇒ g2_on 自动归 0，模块其余功能照常。
 *
 * 【学习型鉴权（继承 v2.0.1，不可伪造）】
 *   判据 = "鉴权门后的命令返回 ret >= 0"（superkey 或本机 trusted_manager
 *   才可能）。SU 族/HELLO/VER 等门前命令绝不作学习判据。
 *
 * 【符号面】extern 仅 5 个，与 v2.0.1（已在原版 APatch 真机加载成功）完全
 *   一致：current_uid / has_syscall_wrapper / fp_wrap_syscalln /
 *   fp_unwrap_syscalln / kallsyms_lookup_name。
 *   hook / unhook / compat_strncpy_from_user / printk / scnprintf /
 *   copy_to_user / copy_from_kernel_nofault 等一律 kallsyms 运行时解析，
 *   缺失只降级，不造成加载失败。
 * ---------------------------------------------------------------------------
 * 
 * 
 * 
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <common.h>
#include <linux/kernel.h>
#include <kputils.h>          /* current_uid */
#include <hook.h>             /* hook_fargs6_t */
#include <syscall.h>          /* fp_hook_syscalln / syscall_args */
#include <ksyms.h>
#include <kallsyms.h>
#include <baselib.h>
#include <asm/ptrace.h>       /* struct pt_regs（oracle 用调用者 pc） */
#include <uapi/asm-generic/errno.h>

KPM_NAME("APKey_Hide");
KPM_VERSION("2.1.3");
KPM_LICENSE("MIT");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("suppress KernelPatch supercall param-page reads;https://github.com/Lun-OS/APKey_Hide_KPM");

/* ========================== 常量 ========================== */
#define APK_NR_SUPERCALL    45
#define APK_CMD_MIN         0x1000
#define APK_CMD_MAX         0x1200
#define APK_VER_MAX         0xFFFFFFu
#define APK_LEARN_MAX       8
#define APK_ALLOW_MAX       8
#define APK_XX_MAGIC        0x1158u   /* 仅作学习参考值，不作信任判据 */

/* 页表研判（移植自 v1.0.0 真机调通版） */
#define APK_ID_BYTES        64              /* 标定内容比对长度 */
#define APK_PHYS_MAX        0x4000000000ULL
#define APK_PHYS_MASK_MAX   0x0000FFFFFFFFF000ULL
#define APK_PTE_USER        (1ULL << 6)     /* arm64 LPAE AP[1] */
#define APK_DRAIN_LOOPS     400000000UL     /* 卸载排空在途 stub */
#define APK_SCFU_KEY_LEN    128             /* G2 count 门控 = MAX_KEY_LEN。审计结论：
   * KP 里对【任意 uid 无条件】执行的用户页读取只有 supercall before() 的
   *   compat_strncpy_from_user(key, x0, MAX_KEY_LEN=128) —— 这就是页侧信道
   *   唯一入口，也是检测器靶点（execve 魔法路径 key 读取 count=SUPER_KEY_LEN=64，
   *   ≤128 一并覆盖）。其余 scfu 调用点（KLOG=1024 / kpm_load=1024 / su 写…）
   *   全在 `if(!is_trusted_caller)return` 门后，未授权检测器触发不到 ⇒ 扩大门控
   *   无收益，反而可能误伤 su_allow app 的 KLOG。故精准锁定 128。 */

/* ========================== 日志 ========================== */
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

/* ========================== 基础工具（无 libc） ========================== */

/* ========================== 架构寄存器 ========================== */
static inline uint64_t apk_mrs_ttbr0(void)
{
    uint64_t v; asm volatile("mrs %0, ttbr0_el1" : "=r"(v)); return v;
}
static inline uint64_t apk_mrs_ttbr1(void)
{
    uint64_t v; asm volatile("mrs %0, ttbr1_el1" : "=r"(v)); return v;
}
static inline uint64_t apk_mrs_tcr(void)
{
    uint64_t v; asm volatile("mrs %0, tcr_el1" : "=r"(v)); return v;
}
static inline uint64_t apk_mrs_mair(void)
{
    uint64_t v; asm volatile("mrs %0, mair_el1" : "=r"(v)); return v;
}

/* ========================== 可调参数 ========================== */
static int apk_learn_on = 1;   /* 学习型鉴权 */
static int apk_purify_on = 1;  /* 返回值净化（通道 A） */
static int apk_g2_on = 1;      /* 页守卫（通道 B；失败自动降级 0） */
static int apk_trace;          /* ctl0 trace=1：nr45 现场记录（debug 版） */

/* ========================== 学习集合 ========================== */
static uint32_t apk_learn_ids[APK_LEARN_MAX];
static int      apk_learn_n;

static uint32_t apk_allow[APK_ALLOW_MAX] = {0};
static int      apk_allow_n = 1;

static uint32_t apk_xx_learned;   /* 从受信调用者学到的 xx magic（仅参考） */

static void apk_learn_add(uint32_t uid)
{
    int i;
    for (i = 0; i < apk_learn_n; i++)
        if (apk_learn_ids[i] == uid) return;
    if (apk_learn_n < APK_LEARN_MAX) {
        apk_learn_ids[apk_learn_n++] = uid;
        APK_LOG("learned uid=%u n=%d\n", (unsigned)uid, apk_learn_n);
    }
}

static int apk_learn_has(uint32_t uid)
{
    int i;
    for (i = 0; i < apk_learn_n; i++)
        if (apk_learn_ids[i] == uid) return 1;
    return 0;
}

static int apk_uid_trusted(uint32_t u)
{
    int i;
    if (apk_learn_has(u)) return 1;
    for (i = 0; i < apk_allow_n; i++)
        if (apk_allow[i] == u) return 1;
    return 0;
}

/* 鉴权门后的命令族：supercall.c 中全部 case 位于
 *   `if (!is_authed) return -EPERM;`
 * 之后 ⇒ 未鉴权必为负，ret >= 0 即不可伪造的管理器证明。
 * ★ HELLO(0x1000)/KLOG(0x1004)/VER(0x1007/0x1009)/SU 族(0x1100+) 在门前，
 *   绝不可作学习判据（会被检测器污染学习集）。 */
static int apk_is_postgate_cmd(uint64_t cmd)
{
    switch (cmd) {
    case 0x1020:  /* SUPERCALL_KPM_LOAD     成功返回 0 */
    case 0x1021:  /* SUPERCALL_KPM_UNLOAD */
    case 0x1022:  /* SUPERCALL_KPM_CONTROL */
    case 0x1030:  /* SUPERCALL_KPM_NUMS     返回模块数 >= 1 */
    case 0x1031:  /* SUPERCALL_KPM_LIST */
    case 0x100a:  /* SUPERCALL_SKEY_GET */
    case 0x100b:  /* SUPERCALL_SKEY_SET */
    case 0x100c:  /* SUPERCALL_SKEY_ROOT_ENABLE */
        return 1;
    default:
        return 0;
    }
}

/* ========================== 运行时解析符号 ============ */
static long (*apk_nofault_r)(void *dst, const void *src, size_t n);
static int  (*apk_snprintf)(char *buf, size_t sz, const char *fmt, ...);
static long (*apk_copy_to_user)(void *to, const void *from, unsigned long n);

/* ★ hook / unhook / compat_strncpy_from_user 是 **KP 导出表**符号
 *   （KP_EXPORT_SYMBOL），内核 /proc/kallsyms 里没有 —— kallsyms_lookup_name
 *   ("hook") 实测返回 NULL（v2.1.0/2.1.1 g2 因此全程 off）。正确用法 = 直接
 *   extern 声明，由 KPM 加载器从 KP 符号表解析（LH_Dr_KPM 的 nm -u 权威集
 *   含 hook/unhook，已在原版 APatch 真机加载成功）。声明来自 <hook.h> /
 *   <kputils.h>，此处不重复定义。 */

/* 原生 nr45（truncate）入口：净化时还原 origin 语义 */
static uintptr_t apk_orig45;

/* ========================== 计数（status） ========================== */
static volatile uint32_t apk_n_pass;    /* 受信放行 */
static volatile uint32_t apk_n_learn;   /* 学习成功 */
static volatile uint32_t apk_n_purify;  /* 净化（改写 ret） */
static volatile uint32_t apk_n_native;  /* KP 未认领，原生执行 */
static volatile uint32_t apk_n_absent;  /* 页研判：确信缺失 */
static volatile uint32_t apk_n_g2;      /* G2 拦截次数 */
static volatile uint32_t apk_n_g2o;     /* G2 放行次数（present/受信） */

/* 钩子状态 */
static int apk_hooked;
static int apk_g2_installed;            /* G2 inline hook 已装 */
static volatile int apk_g2_inflight;    /* 在途 stub 计数（卸载排空） */

/* ==========================================================================
 * 一、用户页表研判（移植自 v1.0.0，真机调通；运行时解析、不碰用户内存）
 * ========================================================================== */
static int      apk_walk_ok;     /* 线性映射偏移已内容验证 */
static int      apk_walk_ver;    /* 已被 oracle 武装（G2 硬前提） */
static int      apk_st_done;     /* oracle 已尝试 */
static uint64_t apk_lin_off;
static uint64_t apk_upgd;        /* 当前进程用户 PGD 的线性别名 VA */
static uint64_t apk_mair;        /* 必须 64 位：AttrIndx4..7 在 bits[39:32] */
static int      apk_ubits;       /* 用户 VA 位宽 39/48 */
static int      apk_ups;         /* 用户页大小 log2 */
static int      apk_ulevel;      /* 用户页表级数 */

static inline uint64_t apk_phys_mask(int shift)
{
    return (~((1ULL << shift) - 1)) & APK_PHYS_MASK_MAX;
}




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

*/




/* 解析 va 叶子描述符；0 = present（用户映射、非 Device） */
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
            return -1;

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
                return -1;
            base = next_pa + lin_off;
        }
    }

    idx = (int)((va >> ps) & 0x1FF);         /* PTE 级 */
    if (apk_nofault_r(&ent, (void *)(base + (uint64_t)idx * 8), 8) != 0)
        return -1;
    if ((ent & 0x3) != 0x3)
        return -1;
    *out_pa = (ent & apk_phys_mask(ps)) | (va & ((1ULL << ps) - 1));
    *out_leaf_va = base + (uint64_t)idx * 8;
    *out_leaf = ent;
    *out_blk = ps;

leaf_check:
    if (require_user && !(ent & APK_PTE_USER))
        return -1;
    if (apk_mair) {
        uint8_t attr = (uint8_t)((apk_mair >> (((ent >> 2) & 7) * 8)) & 0xFF);
        if ((attr & 0xF0) == 0)
            return -2;                       /* Device：拒绝线性映射读 */
    }
    return 0;
}

/* TTBR0 每进程不同 ⇒ 每次判定前刷新（一条 mrs + 加法）。保留 BADDR 全部
 * 有效位，只清 ASID([63:48]) 与 4KB 以下低位（CnP/保留位） */
static void apk_refresh_upgd(void)
{
    uint64_t t = apk_mrs_ttbr0() & ((1ULL << 48) - 1) & ~0xFFFULL;
    apk_upgd = t ? (t + apk_lin_off) : 0;
}

/* va 所在用户页是否已换入（present 且用户映射） */
static int apk_page_present(uint64_t va)
{
    uint64_t pa = 0, leaf_va = 0, leaf = 0;
    int blk = 0;

    if (!apk_upgd || !va)
        return 0;
    return apk_walk(apk_upgd, va, apk_ups, apk_ulevel, 1, apk_lin_off,
                    &pa, &leaf_va, &leaf, &blk) == 0;
}

/* 确信"页不可用"（无有效用户 PTE）—— G2 唯一放行拦截的判据；
 * 任何不确定（未标定/未武装/TTBR0 不可用）一律返回 0（fail-open）。 */
static int apk_user_page_absent(uint64_t va)
{
    if (!apk_walk_ok || !apk_walk_ver)
        return 0;
    if (va < 0x1000)
        return 1;
    if (va >= (1ULL << apk_ubits))
        return 1;                            /* 内核地址/非法 */
    apk_refresh_upgd();
    if (!apk_upgd)
        return 0;
    if (apk_page_present(va))
        return 0;
    apk_n_absent++;
    return 1;
}

/* 线性映射偏移候选：PAGE_OFFSET 历史公式 × 是否减 memstart，全部靠内容比对择优 */
static int apk_po_candidates(uint64_t *out, int max)
{
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
        po = (k < 2) ? ~((1ULL << (vb - 1)) - 1) : ~((1ULL << vb) - 1) + 1;
        dup = 0;
        for (i = 0; i < n; i++)
            if (out[i] == po) dup = 1;
        if (!dup && n < max)
            out[n++] = po;
        if (memstart) {
            dup = 0;
            for (i = 0; i < n; i++)
                if (out[i] == po - memstart) dup = 1;
            if (!dup && n < max)
                out[n++] = po - memstart;
        }
    }
    return n;
}

/* 从 TCR_EL1 推导用户侧位宽/页大小/级数（确定性） */
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

/* ---- 标定路径 A：kimage_voffset 直接拿 (_text VA, PA) 对，内容比对锁定线性
 * 偏移。全程只读内核内存，零副作用，不依赖页表遍历。 ---- */
static int apk_calib_kimage(void)
{
    unsigned char ref[APK_ID_BYTES];
    uint64_t kimg_sym = (uint64_t)(uintptr_t)kallsyms_lookup_name("kimage_voffset");
    uint64_t text_va = (uint64_t)(uintptr_t)kallsyms_lookup_name("_text");
    uint64_t kv = 0, text_pa;
    uint64_t cands[16];
    int n, i, k, ok;

    if (!text_va)
        text_va = (uint64_t)(uintptr_t)kallsyms_lookup_name("_stext");
    if (!kimg_sym || !text_va)
        return 0;
    if (apk_nofault_r(&kv, (void *)kimg_sym, 8) != 0 || !kv)
        return 0;
    text_pa = text_va - kv;
    if (text_pa < 0x1000 || text_pa >= APK_PHYS_MAX)
        return 0;

    for (i = 0; i < APK_ID_BYTES; i++)
        if (apk_nofault_r(&ref[i], (void *)(text_va + (uint64_t)i), 1) != 0)
            return 0;

    n = apk_po_candidates(cands, 16);
    for (i = 0; i < n; i++) {
        ok = 1;
        for (k = 0; k < APK_ID_BYTES; k++) {
            unsigned char b = 0;
            if (apk_nofault_r(&b, (void *)(text_pa + cands[i] + (uint64_t)k), 1) != 0
                || b != ref[k]) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            apk_lin_off = cands[i];
            APK_LOG("calib A OK lin=%llx\n", (unsigned long long)cands[i]);
            return 1;
        }
    }
    return 0;
}

/* ---- 标定路径 B（兜底）：TTBR1 页表遍历 + swapper_pg_dir 可读性筛选 +
 * _stext 内容比对。MAIR 必须先取（否则叶子全被误判 Device）。 ---- */
static int apk_verify_offset(uint64_t d, uint64_t kpgd, uint64_t stext_va,
                             int kbits, int kps)
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
        return 0;

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










/***
 *               ii.                                         ;9ABH,          
 *              SA391,                                    .r9GG35&G          
 *              &#ii13Gh;                               i3X31i;:,rB1         
 *              iMs,:,i5895,                         .5G91:,:;:s1:8A         
 *               33::::,,;5G5,                     ,58Si,,:::,sHX;iH1        
 *                Sr.,:;rs13BBX35hh11511h5Shhh5S3GAXS:.,,::,,1AG3i,GG        
 *                .G51S511sr;;iiiishS8G89Shsrrsh59S;.,,,,,..5A85Si,h8        
 *               :SB9s:,............................,,,.,,,SASh53h,1G.       
 *            .r18S;..,,,,,,,,,,,,,,,,,,,,,,,,,,,,,....,,.1H315199,rX,       
 *          ;S89s,..,,,,,,,,,,,,,,,,,,,,,,,....,,.......,,,;r1ShS8,;Xi       
 *        i55s:.........,,,,,,,,,,,,,,,,.,,,......,.....,,....r9&5.:X1       
 *       59;.....,.     .,,,,,,,,,,,...        .............,..:1;.:&s       
 *      s8,..;53S5S3s.   .,,,,,,,.,..      i15S5h1:.........,,,..,,:99       
 *      93.:39s:rSGB@A;  ..,,,,.....    .SG3hhh9G&BGi..,,,,,,,,,,,,.,83      
 *      G5.G8  9#@@@@@X. .,,,,,,.....  iA9,.S&B###@@Mr...,,,,,,,,..,.;Xh     
 *      Gs.X8 S@@@@@@@B;..,,,,,,,,,,. rA1 ,A@@@@@@@@@H;........,,,,,,.iX:    
 *     ;9. ,8A#@@@@@@#5,.,,,,,,,,,... 9A. 8@@@@@@@@@@M;    ....,,,,,,,,S8    
 *     X3    iS8XAHH8s.,,,,,,,,,,...,..58hH@@@@@@@@@Hs       ...,,,,,,,:Gs   
 *    r8,        ,,,...,,,,,,,,,,.....  ,h8XABMMHX3r.          .,,,,,,,.rX:  
 *   :9, .    .:,..,:;;;::,.,,,,,..          .,,.               ..,,,,,,.59  
 *  .Si      ,:.i8HBMMMMMB&5,....                    .            .,,,,,.sMr
 *  SS       :: h@@@@@@@@@@#; .                     ...  .         ..,,,,iM5
 *  91  .    ;:.,1&@@@@@@MXs.                            .          .,,:,:&S
 *  hS ....  .:;,,,i3MMS1;..,..... .  .     ...                     ..,:,.99
 *  ,8; ..... .,:,..,8Ms:;,,,...                                     .,::.83
 *   s&: ....  .sS553B@@HX3s;,.    .,;13h.                            .:::&1
 *    SXr  .  ...;s3G99XA&X88Shss11155hi.                             ,;:h&,
 *     iH8:  . ..   ,;iiii;,::,,,,,.                                 .;irHA  
 *      ,8X5;   .     .......                                       ,;iihS8Gi
 *         1831,                                                 .,;irrrrrs&@
 *           ;5A8r.                                            .:;iiiiirrss1H
 *             :X@H3s.......                                .,:;iii;iiiiirsrh
 *              r#h:;,...,,.. .,,:;;;;;:::,...              .:;;;;;;iiiirrss1
 *             ,M8 ..,....,.....,,::::::,,...         .     .,;;;iiiiiirss11h
 *             8B;.,,,,,,,.,.....          .           ..   .:;;;;iirrsss111h
 *            i@5,:::,,,,,,,,.... .                   . .:::;;;;;irrrss111111
 *            9Bi,:,,,,......                        ..r91;;;;;iirrsss1ss1111
 * 
 * 
 * 
 * 
 */
 











static int apk_calib_kernel(void)
{
    uint64_t tcr = apk_mrs_tcr();
    uint64_t stext_va;
    uint64_t baddr1;
    uint64_t cands[16];
    int n, i, x, y, done = 0;

    if (!apk_nofault_r)
        return 0;

    stext_va = (uint64_t)(uintptr_t)kallsyms_lookup_name("_stext");
    baddr1 = apk_mrs_ttbr1() & ((1ULL << 48) - 1) & ~0xFFFULL;
    if (!stext_va || !baddr1)
        return 0;

    n = apk_po_candidates(cands, 16);
    if (!n)
        return 0;

    {   /* 先筛掉线性别名不可读的候选（偏移错 ⇒ 指向未映射 VA） */
        int nn = 0;
        uint64_t keep[16];
        for (i = 0; i < n; i++) {
            uint64_t ent0 = 0;
            if (apk_nofault_r(&ent0, (void *)(baddr1 + cands[i]), 8) == 0)
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
        /* TG1 编码与 TG0 不同：0b01=16KB, 0b10=4KB, 0b11=64KB */
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
    }
    if (done)
        APK_LOG("calib B OK lin=%llx\n", (unsigned long long)apk_lin_off);
    return done;
}

/* oracle：调用者 PC 所在页必然 present（马上要从它返回执行）。
 * 遍历若说"不可用" ⇒ 标定/参数错了 ⇒ 永久 fail-open。 */
static void apk_walk_sanity(uint64_t pc)
{
    apk_refresh_upgd();
    if (!apk_upgd) {
        apk_walk_ok = 0;
        APK_LOG("oracle upgd=0 -> walk off\n");
        return;
    }
    if (!apk_page_present(pc & ~0xFFFULL)) {
        apk_walk_ok = 0;
        APK_LOG("oracle pc=%llx NOT present -> walk off\n",
                (unsigned long long)pc);
        return;
    }
    apk_walk_ver = 1;
    APK_LOG("oracle pc=%llx present -> walk armed\n", (unsigned long long)pc);
}

/* ==========================================================================
 * 二、G2 守卫：compat_strncpy_from_user 内联钩子（页侧信道拦截点）
 *
 *   四道门（见文件头"误判防线"）：g2_on + walk_ver + 非受信 uid + 页确信缺失。
 *   拦截 = 返回 0（= 懒页空串的逐字节等价读法，页零副作用）。
 *   KP 拿到 len<=0 ⇒ return ⇒ skip_origin=0 ⇒ 原生 truncate 语义完整。
 * ========================================================================== */
static long (*apk_orig_scfu)(char *dest, const char __user *src, long count);

/* 在途计数：必须原子（多核同时进 stub，非原子读-改-写会丢计数 ⇒
 * 卸载排空提前通过 ⇒ 在途 stub 撞已释放 .text ⇒ 概率性 panic）。
 * ★ 不用 __atomic 系列 / __sync 系列（生成 libgcc 辅助调用 ⇒ KPM 加载失败），
 *   与 LH_Dr_KPM 相同用 ldaxr/stlxr 裸汇编。 */
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

static long apk_g2_scfu(char *dest, const char __user *src, long count)
{
    uint32_t uid;
    long r;

    apk_atomic_inc((volatile int *)&apk_g2_inflight);

    if (apk_g2_on && apk_walk_ver) {
        uid = (uint32_t)current_uid();
        if (!apk_uid_trusted(uid) && src && count > 0 &&
            count <= APK_SCFU_KEY_LEN &&
            apk_user_page_absent((uint64_t)(uintptr_t)src)) {
            apk_n_g2++;
            APK_LOG("g2 block uid=%u src=%llx n=%u\n", (unsigned)uid,
                    (unsigned long long)(uintptr_t)src, (unsigned)apk_n_g2);
            apk_atomic_dec((volatile int *)&apk_g2_inflight);
            return 0;
        }
        apk_n_g2o++;
    }

    if (apk_orig_scfu)
        r = apk_orig_scfu(dest, src, count);
    else
        r = -EFAULT;                     /* 理论不可达：orig 为空则不会装钩 */
    apk_atomic_dec((volatile int *)&apk_g2_inflight);
    return r;
}

/* ========================== 净化：KP 泄漏值的原生语义 ========================== */
static long apk_native_ret(void *fdata, uint64_t x0, uint64_t x1)
{
    /* 干净内核 truncate：length<0 在 getname 前返回 -EINVAL，
     * 一个字节都不读 x0 ⇒ 同值返回，页侧信道零差异。 */
    if ((long)x1 < 0)
        return -EINVAL;

    if (apk_orig45) {
        /* wrapper 模式：transit 抓到的 args[0] 本身就是 pt_regs* 指针 */
        if (has_syscall_wrapper)
            return ((long (*)(struct pt_regs *))apk_orig45)(
                (struct pt_regs *)((hook_fargs6_t *)fdata)->args[0]);
        return ((long (*)(uint64_t, uint64_t))apk_orig45)(x0, x1);
    }
    return -ENOENT;
}


/* ---------------- nr45 before：KP supercall 钩子（链槽 0）之后 ---------------- */
static void apk_sc45_before(hook_fargs6_t *fargs, void *udata)
{
    uint64_t *args;
    uint64_t x0, x1, cmd;
    uint32_t uid;
    long kret;

    (void)udata;

    args = syscall_args(fargs);
    x0 = args[0];
    x1 = args[1];
    cmd = x1 & 0xFFFF;

    uid = (uint32_t)current_uid();

    /* 首次进 nr45：oracle 武装（用调用者用户 PC 验证页表遍历正确性）。
     * ★v2.1.1 修正 PAN 崩溃：transit 原始 fargs->args[0] 才是内核栈上的
     *   pt_regs 指针；syscall_args() 解引用后的 args[0] 是**用户 x0**，
     *   把它当 pt_regs* 读 ->pc 触发 "kernel access to user memory" Oops。
     *   再叠加高半内核位校验，双重保险。非 wrapper 时 walk_ver 保持 0 ⇒
     *   G2 永不拦截（fail-open，返回值通道不受影响）。 */
    if (!apk_st_done && apk_walk_ok && !apk_walk_ver) {
        apk_st_done = 1;
        if (has_syscall_wrapper) {
            uint64_t p = fargs->args[0];
            if ((p >> 48) == 0xFFFF) {         /* 内核 VA 才允许解引用 */
                struct pt_regs *regs = (struct pt_regs *)p;
                uint64_t pc = regs->pc;
                if (pc && pc < (1ULL << apk_ubits))
                    apk_walk_sanity(pc);
            }
        } else {
            APK_LOG("oracle: no wrapper -> G2 stays unarmed\n");
        }
    }

    if (apk_trace)
        APK_LOG("t uid=%u x1=%llx cmd=%llx skip=%d ret=%llx\n", (unsigned)uid,
                (unsigned long long)x1, (unsigned long long)cmd,
                (int)fargs->skip_origin, (unsigned long long)fargs->ret);

    /* ---- KP 未认领（未鉴权且非受信）：原生 truncate 照跑，干净，不干预 ---- */
    if (!fargs->skip_origin) {
        apk_n_native++;
        return;
    }

    /* ---- KP 已认领 ---- */
    kret = (long)fargs->ret;

    if (apk_uid_trusted(uid)) {
        apk_n_pass++;
        if (!apk_xx_learned) {
            uint32_t ver = (uint32_t)(x1 >> 32);
            uint32_t xx  = (uint32_t)((x1 >> 16) & 0xFFFFu);
            if (ver != 0 && ver <= APK_VER_MAX && xx != 0) {
                apk_xx_learned = xx;
                APK_LOG("learned xx magic=0x%x from uid=%u\n", xx, (unsigned)uid);
            }
        }
        return;                          /* 放行 KP 的结果（管理器全功能） */
    }

    /* ---- 未受信 + KP 认领：学习 或 净化 ---- */
    if (apk_learn_on && apk_is_postgate_cmd(cmd) && kret >= 0) {
        /* 鉴权门后命令 ret >= 0 ⇒ 真实通过 KP 鉴权（superkey/trusted_manager）
         * —— 检测器无 key 永远做不到 ⇒ 判据不可伪造。 */
        apk_learn_add(uid);
        apk_n_learn++;
        return;                          /* 首次调用即拿到正确结果 */
    }

    if (!apk_purify_on)
        return;

    /* 净化：KP 泄漏的 kpver/magic/-EPERM 改写为原生 truncate 语义 */
    fargs->ret = (uint64_t)apk_native_ret(fargs, x0, x1);
    apk_n_purify++;
    APK_LOG("purify uid=%u cmd=0x%llx kret=%ld -> %ld\n",
            (unsigned)uid, (unsigned long long)cmd, kret, (long)fargs->ret);
}

static void apk_sc45_after(hook_fargs6_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
}

/* ==========================================================================
 * 三、KPM_CTL0
 * ========================================================================== */
static int apk_str_prefix(const char *s, const char *p)
{
    while (*p) { if (*s++ != *p++) return 0; }
    return 1;
}

static int apk_str_eq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a == (unsigned char)*b;
}

static void apk_status_line(char *buf, int buflen)
{
    if (!buf || buflen <= 0) return;
    buf[0] = '\0';
    if (!apk_snprintf) return;

    apk_snprintf(buf, (size_t)buflen,
                 "APKey_Hide v2.1.3 hooked=%d learn=%d(ln=%d) purify=%d g2=%d "
                 "alw=%d xx=0x%x walk(ok=%d ver=%d lin=%llx u%d ps%d lv%d) "
                 "cnt(pass=%u learn=%u pur=%u nat=%u abs=%u g2=%u g2o=%u) o45=%llx",
                 apk_hooked, apk_learn_on, apk_learn_n, apk_purify_on, apk_g2_on,
                 apk_allow_n, (unsigned)apk_xx_learned,
                 apk_walk_ok, apk_walk_ver,
                 (unsigned long long)apk_lin_off, apk_ubits, apk_ups, apk_ulevel,
                 (unsigned)apk_n_pass, (unsigned)apk_n_learn,
                 (unsigned)apk_n_purify, (unsigned)apk_n_native,
                 (unsigned)apk_n_absent, (unsigned)apk_n_g2, (unsigned)apk_n_g2o,
                 (unsigned long long)(uintptr_t)apk_orig45);
    buf[buflen - 1] = '\0';
}

long apk_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char cmd[24];
    char out[480];
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
            const char *q = cmd + 6;
            apk_allow_n = 0;
            if (!(q[0] == 'n')) {
                while (*q && apk_allow_n < APK_ALLOW_MAX) {
                    uint32_t v = 0;
                    while (*q >= '0' && *q <= '9')
                        v = v * 10u + (uint32_t)(*q++ - '0');
                    apk_allow[apk_allow_n++] = v;
                    if (*q == ',') q++; else break;
                }
            }
        } else if (apk_str_eq(cmd, "reset")) {
            int i;
            for (i = 0; i < APK_LEARN_MAX; i++) apk_learn_ids[i] = 0;
            apk_learn_n = 0;
            apk_xx_learned = 0;
        } else if (apk_str_prefix(cmd, "learn=")) {
            apk_learn_on = (cmd[6] == '1');
        } else if (apk_str_prefix(cmd, "purify=")) {
            apk_purify_on = (cmd[7] == '1');
        } else if (apk_str_prefix(cmd, "g2=")) {
            apk_g2_on = (cmd[3] == '1');
        } else if (apk_str_prefix(cmd, "trace=")) {
            apk_trace = (cmd[6] == '1');
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

/* ==========================================================================
 * 四、安装 / 卸载
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

/* 把 G2 inline hook 装到 KP 的 compat_strncpy_from_user 上。
 * hook/unhook/compat_strncpy_from_user 全部 extern（KP 导出表解析，
 * 见上方说明）。失败 ⇒ 永久降级 g2_on=0（返回值通道不受影响）。 */
static int apk_install_g2(void)
{
    hook_err_t err;

    err = hook((void *)compat_strncpy_from_user, (void *)apk_g2_scfu,
               (void **)&apk_orig_scfu);
    if (err || !apk_orig_scfu) {
        APK_LOG("g2: hook failed err=%d -> off\n", (int)err);
        apk_orig_scfu = 0;
        return 0;
    }
    APK_LOG("g2: armed at scfu=%llx\n",
            (unsigned long long)(uintptr_t)compat_strncpy_from_user);
    return 1;
}

static long apk_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;

    (void)args; (void)event; (void)reserved;

    /* ---- 运行时解析（缺失只降级，不影响加载） ---- */
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
    apk_nofault_r = (long (*)(void *, const void *, size_t))
        kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!apk_nofault_r)
        apk_nofault_r = (long (*)(void *, const void *, size_t))
            kallsyms_lookup_name("probe_kernel_read");

    apk_resolve_orig45();

    /* ---- 页表标定（全程只读内核内存，零副作用） ---- */
    apk_mair = apk_mrs_mair();
    if (apk_nofault_r) {
        apk_user_params_from_tcr();
        apk_walk_ok = apk_calib_kimage();
        if (!apk_walk_ok)
            apk_walk_ok = apk_calib_kernel();
    }

    /* ---- G2 内联钩子（oracle 在首次 nr45 时武装） ---- */
    if (apk_g2_on && apk_walk_ok)
        apk_g2_installed = apk_install_g2();
    if (!apk_g2_installed)
        apk_g2_on = 0;

    /* ---- nr45 链钩子（与 v2.0.1 相同、真机验证过的 API） ---- */
    err = fp_hook_syscalln(APK_NR_SUPERCALL, 6,
                           (void *)apk_sc45_before, (void *)apk_sc45_after, 0);
    if (err) {
        APK_LOG("fp_hook_syscalln(45) failed: %d\n", (int)err);
        if (apk_g2_installed) {
            unhook((void *)compat_strncpy_from_user);
            apk_g2_installed = 0;
            apk_g2_on = 0;
        }
        return -1;
    }
    apk_hooked = 1;

    APK_LOG("init v2.1.3 done o45=%llx walk=%d g2=%d\n",
            (unsigned long long)apk_orig45, apk_walk_ok, apk_g2_installed);
    return 0;
}

static long apk_exit(void *reserved)
{
    unsigned long spins = 0;

    (void)reserved;

    /* 停机顺序：先摘最外层 nr45（不再产生新的 scfu 读取上下文），
     * 再摘 G2 inline hook，排空在途 stub 后模块 .text 才可安全释放。 */
    if (apk_hooked) {
        fp_unhook_syscalln(APK_NR_SUPERCALL,
                           (void *)apk_sc45_before, (void *)apk_sc45_after);
        apk_hooked = 0;
    }
    if (apk_g2_installed) {
        apk_g2_on = 0;
        unhook((void *)compat_strncpy_from_user);
        /* hook() 的 trampoline 备份在 apk_orig_scfu，unhook 即恢复原函数头；
         * 再排空在途 stub（都在模块 .text 内，必须等它们退出） */
        while (apk_g2_inflight != 0 && spins < APK_DRAIN_LOOPS)
            spins++;
        apk_g2_installed = 0;
        apk_orig_scfu = 0;
    }
    APK_LOG("exit done\n");
    return 0;
}

KPM_INIT(apk_init);
KPM_EXIT(apk_exit);
