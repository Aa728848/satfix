#ifndef SATFIX_DEBUG_UI_HPP
#define SATFIX_DEBUG_UI_HPP
//
// ImGui 调试窗口：舰队索敌权重（debug_target_weight）
//
// 关键前提（已核实）：**群星自带 ImGui**，OpenGL3 后端、符号全部导出，
// 所以完全不需要自己注入 ImGui / 接管渲染：
//
//   ImGui::NewFrame  @0x3f1d620   ImGui::Begin @0x3f22680   ImGui::End @0x3f297b0
//   ImGui::Checkbox  @0x3f95bc0   ImGui::SmallButton @0x3f94910
//   ImGui::TextUnformatted @0x3f93510   ImGui::Separator @0x3f96d70
//   ImGui::SetNextWindowSize @0x3f22650
//
// 做法：hook ImGui::NewFrame，调完原函数后画自己的窗口。NewFrame 之后、Render 之前
// 本来就是各窗口自己 Begin/End 的位置，所以不动游戏原有 UI，也不改帧结构。
//
#include "shk.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace satfix_ui {

/// 和 ImVec2 二进制兼容（两个 float）
struct Vec2
{
    float x, y;
};

using NewFrameFn          = void (*)();
using BeginFn             = bool (*)(const char* name, bool* p_open, int flags);
using EndFn               = void (*)();
using TextUnformattedFn   = void (*)(const char* text, const char* text_end);
using SeparatorFn         = void (*)();
using CheckboxFn          = bool (*)(const char* label, bool* v);
using SmallButtonFn       = bool (*)(const char* label);
using SetNextWindowSizeFn = void (*)(const Vec2* size, int cond);
using GetIOFn             = void* (*)();
using AddFontFromFileTTFFn = void* (*)(void* atlas, const char* filename, float size,
                                       const void* cfg, const unsigned short* ranges);
using GlyphRangesCJKFn    = const unsigned short* (*)();
using PushFontFn          = void (*)(void* font);
using PopFontFn           = void (*)();

NewFrameFn          p_NewFrame          = nullptr;
BeginFn             p_Begin             = nullptr;
EndFn               p_End               = nullptr;
TextUnformattedFn   p_Text              = nullptr;
SeparatorFn         p_Separator         = nullptr;
CheckboxFn          p_Checkbox          = nullptr;
SmallButtonFn       p_SmallButton       = nullptr;
SetNextWindowSizeFn p_SetNextWindowSize = nullptr;
GetIOFn             p_GetIO             = nullptr;
AddFontFromFileTTFFn p_AddFont          = nullptr;
GlyphRangesCJKFn    p_GlyphRangesCJK    = nullptr;
PushFontFn          p_PushFont          = nullptr;
PopFontFn           p_PopFont           = nullptr;

void* g_cjk_font = nullptr;   ///< 装好的中文字体（ImFont*）

/// ImGuiIO 里 Fonts 字段的偏移 —— 在 ImGui_ImplOpenGL3 的建纹理代码里读到：
///   io = ImGui::GetIO();  ... *(ImFontAtlas**)(io + 0xa0)
constexpr size_t kImGuiIO_Fonts = 0xa0;

/// 用游戏自带的 CJK 字体给我们的窗口加中文字形。
/// 必须在**第一次 NewFrame 之前**做，所以放在 hook 的最前面、调原函数之前。
void ensure_cjk_font()
{
    static bool tried = false;
    if(tried)
        return;
    tried = true;
    if(p_GetIO == nullptr || p_AddFont == nullptr)
        return;

    void* io = p_GetIO();
    if(io == nullptr)
        return;
    void* atlas = *reinterpret_cast<void**>(static_cast<char*>(io) + kImGuiIO_Fonts);
    if(atlas == nullptr)
        return;

    // 字体就在游戏目录里（gfx/fonts/NotoSansCJKsc-Medium.otf，简体子集、单体 OTF），
    // 从 /proc/self/exe 推目录，避免再写死路径
    char exe[4096];
    const ssize_t n = ::readlink("/proc/self/exe", exe, sizeof exe - 1);
    if(n <= 0)
        return;
    exe[n] = '\0';
    char* slash = std::strrchr(exe, '/');
    if(slash == nullptr)
        return;
    *slash = '\0';
    char font_path[4096];
    std::snprintf(font_path, sizeof font_path, "%s/gfx/fonts/NotoSansCJKsc-Medium.otf", exe);

    const unsigned short* ranges =
        p_GlyphRangesCJK != nullptr ? p_GlyphRangesCJK() : nullptr;
    g_cjk_font = p_AddFont(atlas, font_path, 16.0f, nullptr, ranges);
    std::fprintf(stderr, "[satfix] 中文字体 %s -> %s\n", font_path,
                 g_cjk_font != nullptr ? "已加入字体图集" : "加入失败（窗口中文会显示成 ?）");
}

// ---------------------------------------------------------------------------
// 界面状态 —— 默认值按需求：手动触发 + 不显示组件级权重
// ---------------------------------------------------------------------------
bool g_window_open            = false;   ///< 窗口开关（控制台命令 / 环境变量）
bool g_show_component_weights = false;   ///< 显示每个武器组件的权重？默认否
bool g_periodic               = false;   ///< 定期计算？默认否（手动）
bool g_compute_requested      = false;   ///< 本帧点了"立即计算"

/// 数据快照（真正的索敌权重计算接入后往这里填）
struct Row
{
    char ship[64];
    char target[64];
    int64_t weight;       ///< CFixedPoint，1.0 = 100000
    char component[64];   ///< 组件级才有
};
Row g_rows[256];
int g_row_count = 0;

void clear_rows()
{
    g_row_count = 0;
}

void add_row(const char* ship, const char* target, int64_t weight, const char* component = nullptr)
{
    if(g_row_count >= 256)
        return;
    Row& r = g_rows[g_row_count++];
    std::snprintf(r.ship, sizeof r.ship, "%s", ship != nullptr ? ship : "?");
    std::snprintf(r.target, sizeof r.target, "%s", target != nullptr ? target : "?");
    r.weight = weight;
    std::snprintf(r.component, sizeof r.component, "%s", component != nullptr ? component : "");
}

// ---------------------------------------------------------------------------
// 画窗口
// ---------------------------------------------------------------------------
void draw_window()
{
    if(!g_window_open)
        return;
    // ⚠️ 2026-10-09 20:34 崩溃：ImGui::PushFont(ImFont*)+0x98 SEGV。
    //    AddFontFromFileTTF 返回了非空但已失效的 ImFont*（很可能是因为游戏的字体图集
    //    已经 Build 过，加进去的字体没有真正注册），PushFont 解引用它就炸。
    //    因此**默认不调用 PushFont**，需要时用 SATFIX_CJK_FONT=1 显式打开（风险自负）。
    const bool use_cjk = g_cjk_font != nullptr && p_PushFont != nullptr
                         && std::getenv("SATFIX_CJK_FONT") != nullptr;
    if(use_cjk)
        p_PushFont(g_cjk_font);
    if(p_SetNextWindowSize != nullptr)
    {
        const Vec2 size{560.f, 420.f};
        p_SetNextWindowSize(&size, 0 /* ImGuiCond_Always */);
    }
    if(!p_Begin("debug_target_weight", nullptr, 0))
    {
        p_End();
        return;
    }

    p_Text("舰队索敌权重（debug_target_weight）", nullptr);
    p_Separator();
    p_Checkbox("显示每个武器组件的权重", &g_show_component_weights);
    p_Checkbox("定期计算（默认手动触发）", &g_periodic);
    if(p_SmallButton != nullptr && p_SmallButton("立即计算"))
        g_compute_requested = true;
    p_Separator();

    if(g_row_count == 0)
    {
        p_Text("暂无数据。", nullptr);
        p_Text("窗口与控件已就绪；索敌权重数据源尚未接入，", nullptr);
        p_Text("见 satfix/docs/target_weight_debug.md 的 TODO。", nullptr);
    }
    else
    {
        for(int i = 0; i < g_row_count; ++i)
        {
            const Row& r = g_rows[i];
            char line[256];
            std::snprintf(line, sizeof line, "%-22s -> %-22s  %.4f", r.ship, r.target,
                          static_cast<double>(r.weight) / 1e5);
            p_Text(line, nullptr);
            if(g_show_component_weights && r.component[0] != '\0')
            {
                char sub[256];
                std::snprintf(sub, sizeof sub, "    [组件] %s", r.component);
                p_Text(sub, nullptr);
            }
        }
    }
    p_End();
    if(use_cjk && p_PopFont != nullptr)
        p_PopFont();
}

// ---------------------------------------------------------------------------
// hook ImGui::NewFrame
// ---------------------------------------------------------------------------
shk::TypedHook<NewFrameFn> g_new_frame;

void hook_new_frame()
{
    ensure_cjk_font();                      // 必须在首次 NewFrame 之前加字体
    g_new_frame.call();                     // 先跑游戏自己的 NewFrame
    if(p_Begin != nullptr && p_End != nullptr)
        draw_window();                      // 再画我们的窗口
}

/// 解析 ImGui 入口并安装 hook；任何必需符号缺失就整体放弃（不影响游戏）
bool install()
{
    p_NewFrame = shk::resolve_as<NewFrameFn>("_ZN5ImGui8NewFrameEv");
    p_Begin = shk::resolve_as<BeginFn>("_ZN5ImGui5BeginEPKcPbi");
    p_End = shk::resolve_as<EndFn>("_ZN5ImGui3EndEv");
    p_Text = shk::resolve_as<TextUnformattedFn>("_ZN5ImGui15TextUnformattedEPKcS1_");
    p_Separator = shk::resolve_as<SeparatorFn>("_ZN5ImGui9SeparatorEv");
    p_Checkbox = shk::resolve_as<CheckboxFn>("_ZN5ImGui8CheckboxEPKcPb");
    p_SmallButton = shk::resolve_as<SmallButtonFn>("_ZN5ImGui11SmallButtonEPKc");
    p_SetNextWindowSize = shk::resolve_as<SetNextWindowSizeFn>(
        "_ZN5ImGui17SetNextWindowSizeERK6ImVec2i");
    p_GetIO = shk::resolve_as<GetIOFn>("_ZN5ImGui5GetIOEv");
    p_AddFont = shk::resolve_as<AddFontFromFileTTFFn>(
        "_ZN11ImFontAtlas18AddFontFromFileTTFEPKcfPK12ImFontConfigPKt");
    p_GlyphRangesCJK = shk::resolve_as<GlyphRangesCJKFn>(
        "_ZN11ImFontAtlas37GetGlyphRangesChineseSimplifiedCommonEv");
    p_PushFont = shk::resolve_as<PushFontFn>("_ZN5ImGui8PushFontEP6ImFont");
    p_PopFont = shk::resolve_as<PopFontFn>("_ZN5ImGui7PopFontEv");

    if(p_NewFrame == nullptr || p_Begin == nullptr || p_End == nullptr || p_Text == nullptr
       || p_Checkbox == nullptr)
    {
        std::fprintf(stderr,
                     "[satfix] ImGui 入口没解析全（NewFrame=%p Begin=%p End=%p Text=%p "
                     "Checkbox=%p），调试窗口不启用\n",
                     (void*)p_NewFrame, (void*)p_Begin, (void*)p_End, (void*)p_Text,
                     (void*)p_Checkbox);
        return false;
    }
    if(!g_new_frame.install(reinterpret_cast<void*>(p_NewFrame), &hook_new_frame))
    {
        std::fprintf(stderr, "[satfix] hook ImGui::NewFrame 失败，调试窗口不启用\n");
        return false;
    }

    if(std::getenv("SATFIX_TARGET_WEIGHT") != nullptr)
        g_window_open = true;

    std::fprintf(stderr,
                 "[satfix] ImGui 调试窗口已就绪（NewFrame @ %p）—— 窗口当前 %s；"
                 "控制台命令 debug_target_weight 尚未接入\n",
                 (void*)p_NewFrame, g_window_open ? "打开" : "关闭");
    return true;
}

}  // namespace satfix_ui

#endif  // SATFIX_DEBUG_UI_HPP
