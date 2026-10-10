// ===========================================================================
//  自动生成，不要手改 —— 由 tools/gen_targets.py 产出
//
//  来源二进制 : /home/koishi/SteamLibrary/steamapps/common/Stellaris/stellaris
//  游戏版本串 : v4.5.2  32709cf254181b032b1b309a6ea09776
//  生成时间   : 2026-10-09 20:28:33
//  符号来源   : .dynsym+.symtab
//  命中       : 19/19 targets, 4/4 helpers/23
//
//  重新生成（不传参数就用 satfix.conf / 自动探测到的群星二进制）：
//      tools/gen_targets.py
//      tools/gen_targets.py /path/to/stellaris
//  发现漂移（游戏更新后）：
//      tools/gen_targets.py --check
// ===========================================================================
#ifndef SATFIX_TARGETS_GENERATED_HPP
#define SATFIX_TARGETS_GENERATED_HPP

#include <cstdint>

#define SATFIX_TARGETS_VERSION "v4.5.2  32709cf254181b032b1b309a6ea09776"
#define SATFIX_TARGETS_BINARY  "/home/koishi/SteamLibrary/steamapps/common/Stellaris/stellaris"
#define SATFIX_TARGETS_FOUND   "19/19 targets, 4/4 helpers/23"

// 每一项: X(key, mangled_symbol, fallback_address, description)
// addr == 0 表示这次没在二进制里找到该符号（hook 会被跳过并告警）。
#define SATFIX_TARGETS(X) \
    X(apply_mul_cfx, "_ZN9CModifier17ApplyModifierMultER11CFixedPointRKS_12ModifierTypeb", 0x01d9d700ull, "CModifier::ApplyModifierMult(CFixedPoint&, CModifier const&, ModifierType, bool)") \
    X(apply_mul_fp15, "_ZN9CModifier17ApplyModifierMultERN4fpml11fixed_pointIxLh48ELh15EEERKS_12ModifierTypeb", 0x01d9da00ull, "CModifier::ApplyModifierMult(fpml::fixed_point<...,15>&, ...)") \
    X(cfx_sqrt, "_ZNK11CFixedPoint4SqrtEv", 0x04230850ull, "CFixedPoint::Sqrt() const") \
    X(cfx_safe_sqrt, "_ZNK11CFixedPoint8SafeSqrtEv", 0x04230e20ull, "CFixedPoint::SafeSqrt() const") \
    X(cfx_safe_sqrt_int, "_ZN11CFixedPoint8SafeSqrtEx", 0x04230df0ull, "CFixedPoint::SafeSqrt(long long)") \
    X(cfx_get_rounded, "_ZNK11CFixedPoint10GetRoundedEv", 0x04230860ull, "CFixedPoint::GetRounded() const") \
    X(cfx_get_rounded64, "_ZNK11CFixedPoint12GetRounded64Ev", 0x042308b0ull, "CFixedPoint::GetRounded64() const") \
    X(cfx_round_to, "_ZN11CFixedPoint7RoundToERKS_", 0x04230900ull, "CFixedPoint::RoundTo(CFixedPoint const&)") \
    X(cfx_atan2, "_ZN11CFixedPoint5Atan2ERKS_S1_", 0x042309f0ull, "CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&)") \
    X(cfx_get_rounded_fp15, "_ZN11CFixedPoint10GetRoundedERKN4fpml11fixed_pointIxLh48ELh15EEE", 0x042307e0ull, "CFixedPoint::GetRounded(fpml::fixed_point<...,15> const&)") \
    X(cfx_to_fp15, "_ZNK11CFixedPointcvN4fpml11fixed_pointIxLh48ELh15EEEEv", 0x04230780ull, "CFixedPoint::operator fpml::fixed_point<...,15>() const") \
    X(var_multiply, "_ZNK23CMultiplyVariableEffect13ExecuteActualER11CEventScope", 0x037ca6c0ull, "CMultiplyVariableEffect::ExecuteActual(CEventScope&) const") \
    X(var_add, "_ZNK18CAddVariableEffect13ExecuteActualER11CEventScope", 0x037c98d0ull, "CAddVariableEffect::ExecuteActual(CEventScope&) const") \
    X(mpe15, "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh48ELh15EEES2_", 0x022a3b00ull, "NCombatRules::CalcMilitaryPowerExponent(fpml<...,15>, fpml<...,15>)") \
    X(mpe7, "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh56ELh7EEES2_", 0x022a3e20ull, "NCombatRules::CalcMilitaryPowerExponent(fpml<...,7>, fpml<...,7>)") \
    X(diplo_weight, "_ZNK7CPopJob20CalcDiplomaticWeightERK9CPopGroup", 0x01ea8ed0ull, "CPopJob::CalcDiplomaticWeight(CPopGroup const&) const") \
    X(shield_max, "_ZN9NShipUtil22CalcMaxShieldHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip", 0x01f60900ull, "NShipUtil::CalcMaxShieldHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)") \
    X(armor_max, "_ZN9NShipUtil21CalcMaxArmorHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip", 0x01f61810ull, "NShipUtil::CalcMaxArmorHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)") \
    X(hull_max, "_ZN9NShipUtil16CalcMaxHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip", 0x01f5fa30ull, "NShipUtil::CalcMaxHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)")

// 辅助函数（只解析调用，不 hook）
#define SATFIX_HELPERS(X) \
    X(access_var_pointer, "_Z21AccessVariablePointerR11CEventScopeRK7CString", 0x02120de0ull, "AccessVariablePointer(CEventScope&, CString const&)") \
    X(cvars_get, "_ZNK10CVariables11GetVariableERK7CString", 0x02131560ull, "CVariables::GetVariable(CString const&) const") \
    X(cvars_set, "_ZN10CVariables11SetVariableERK7CString11CFixedPoint", 0x021315b0ull, "CVariables::SetVariable(CString const&, CFixedPoint)") \
    X(cfp_getvalue, "_ZNK24CFixedPointVariableValue8GetValueER11CEventScope", 0x0212ea90ull, "CFixedPointVariableValue::GetValue(CEventScope&) const")

#endif  // SATFIX_TARGETS_GENERATED_HPP
