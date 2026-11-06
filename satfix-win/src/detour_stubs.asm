; ===========================================================================
;  detour_stubs.asm —— 19 个钩子的「寄存器保全」转发桩
;
;  为什么必须有这一层
;  ------------------
;  游戏是用 MSVC /GL（LTCG，全程序优化）编的。LTCG 会做「已知破坏集」传播：
;  编译器知道某个函数实际会写哪些寄存器，于是**允许调用方把值放在它不碰的
;  易失寄存器里跨调用使用**。这不是标准 ABI —— 标准 ABI 里 rax/rcx/rdx/r8-r11
;  都是 caller-saved。但实机反汇编抓到了现行证据（4.5.3，RVA 0xFC5BC5）：
;
;      call 0x141b50ce0     ; CFixedPoint::GetRounded（我们钩了它）
;      mov  edx, eax
;      mov  rcx, r10        ; ← 调用后继续用 r10
;      call r11             ; ← 调用后继续用 r11
;
;  原函数只碰 rax/rcx/rdx，所以 r10/r11 活得好好的；我们的 detour 是普通 C 函数
;  （还会调 logf/原子操作），r10/r11 被改写成垃圾 → `call r11` 跳到栈地址，
;  就是 `c0000005` /「执行栈」的崩溃现场（0x7FEE68、0x7FF078 两次都是它）。
;
;  解决：每个钩子装一个极小的汇编桩，进入时保存**所有易失寄存器**
;  （rcx/rdx/r8-r11 + xmm0-5），调用原来的 C 函数体，返回前原样恢复。
;  这样钩子对游戏的"破坏集"就退化成"一个都不破坏"——比原函数更保守，永远安全。
;
;  帧布局（x64，入口 rsp ≡ 8 mod 16）：
;      push rbp; mov rbp,rsp          ; rbp = 入口 rsp - 8
;      push rcx/rdx/r8/r9/r10/r11     ; 48 字节
;      sub  rsp, 0A0h                 ; 0 mod 16，call 后被调方入口 ≡ 8
;          [rsp+00h..1Fh]  影子空间（C 函数体用）
;          [rsp+20h]       第 5 个参数（从 [rbp+30h] 抄）
;          [rsp+28h]       第 6 个参数（从 [rbp+38h] 抄）
;          [rsp+30h..8Fh]  xmm0-5 保存区
;          [rsp+90h]       返回值（rax）暂存
;      调用 C 函数体 → 恢复 xmm → 取回 rax → 弹栈 → ret
;
;  ⚠️ 新增/删除钩子时：这里要同步加/删一个 STUB，并在 sat_guard_win.cpp 的
;     install_hooks() 里把安装目标从 &detour_xxx 换成 &satfix_stub_xxx。
; ===========================================================================

OPTION CASEMAP:NONE

EXTERN detour_get_rounded:PROC
EXTERN detour_to_fp15:PROC
EXTERN detour_apply_mul:PROC
EXTERN detour_apply_mul_fp15:PROC
EXTERN detour_round_to:PROC
EXTERN detour_atan2:PROC
EXTERN detour_var_mul:PROC
EXTERN detour_var_add:PROC
EXTERN detour_get_rounded_fp15:PROC
EXTERN detour_shield_max:PROC
EXTERN detour_armor_max:PROC
EXTERN detour_hull_max:PROC
EXTERN detour_sqrt:PROC
EXTERN detour_safe_sqrt:PROC
EXTERN detour_diplo_weight:PROC
EXTERN detour_mpe15:PROC
EXTERN detour_mpe7:PROC
EXTERN detour_damage_per_day:PROC
EXTERN detour_ship_size_post_read_init:PROC

STUB MACRO sym, body
    ALIGN 16
sym PROC
    push    rbp
    mov     rbp, rsp
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r10
    push    r11
    sub     rsp, 0A0h
    movaps  xmmword ptr [rsp+030h], xmm0
    movaps  xmmword ptr [rsp+040h], xmm1
    movaps  xmmword ptr [rsp+050h], xmm2
    movaps  xmmword ptr [rsp+060h], xmm3
    movaps  xmmword ptr [rsp+070h], xmm4
    movaps  xmmword ptr [rsp+080h], xmm5
    mov     rax, qword ptr [rbp+30h]
    mov     qword ptr [rsp+20h], rax
    mov     rax, qword ptr [rbp+38h]
    mov     qword ptr [rsp+28h], rax
    call    body
    mov     qword ptr [rsp+90h], rax
    movaps  xmm0, xmmword ptr [rsp+030h]
    movaps  xmm1, xmmword ptr [rsp+040h]
    movaps  xmm2, xmmword ptr [rsp+050h]
    movaps  xmm3, xmmword ptr [rsp+060h]
    movaps  xmm4, xmmword ptr [rsp+070h]
    movaps  xmm5, xmmword ptr [rsp+080h]
    mov     rax, qword ptr [rsp+90h]
    add     rsp, 0A0h
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     rbp
    ret
sym ENDP
ENDM

_TEXT SEGMENT

STUB satfix_stub_get_rounded,        detour_get_rounded
STUB satfix_stub_to_fp15,            detour_to_fp15
STUB satfix_stub_apply_mul,          detour_apply_mul
STUB satfix_stub_apply_mul_fp15,     detour_apply_mul_fp15
STUB satfix_stub_round_to,           detour_round_to
STUB satfix_stub_atan2,              detour_atan2
STUB satfix_stub_var_mul,            detour_var_mul
STUB satfix_stub_var_add,            detour_var_add
STUB satfix_stub_get_rounded_fp15,   detour_get_rounded_fp15
STUB satfix_stub_shield_max,         detour_shield_max
STUB satfix_stub_armor_max,          detour_armor_max
STUB satfix_stub_hull_max,           detour_hull_max
STUB satfix_stub_sqrt,               detour_sqrt
STUB satfix_stub_safe_sqrt,          detour_safe_sqrt
STUB satfix_stub_diplo_weight,       detour_diplo_weight
STUB satfix_stub_mpe15,              detour_mpe15
STUB satfix_stub_mpe7,               detour_mpe7
STUB satfix_stub_damage_per_day,     detour_damage_per_day
STUB satfix_stub_ship_size_max_hp,   detour_ship_size_post_read_init

_TEXT ENDS
END
