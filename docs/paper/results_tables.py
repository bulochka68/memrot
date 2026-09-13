#!/usr/bin/env python3
"""Пересчёт всех числовых таблиц раздела Results (docs/paper/results.md).

Запуск из корня репозитория:

    python3 docs/paper/results_tables.py

Источники чисел (все — артефакты, зафиксированные в репозитории):

* статика — examples/genai_invest_stand.audit.json, examples/mempalace.audit.json
  (отчёты mcp_audit v2, runtime_validation_performed=false);
* каталог сценариев — memrot/catalog/prompts/** (рукописные seed-варианты);
* ручной харнесс — redteam/attacks/test_*.py;
* динамика, прогон R1 (без аудита, широкий свип) — сохранённый вывод
  examples/notebooks/memrot_full_demo.ipynb, Part 1;
* динамика, прогон R2 (аудит-ранжирование) — сохранённый вывод
  examples/notebooks/memrot_presentation_demo.ipynb, Stage 2.

Групповые счётчики вердиктов прогонов R1/R2 внесены сюда как константы: сами
прогоны требуют поднятого стенда и ключей LLM, поэтому воспроизводятся не
скриптом, а командами из README; всё остальное (состав каталога, порядок
ранжирования, кривые обнаружения) вычисляется здесь заново.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from memrot.audit_plan import select_variants_by_audit          # noqa: E402
from memrot.catalog.generator import StaticCatalogGenerator     # noqa: E402

AUDIT_INVEST = "examples/genai_invest_stand.audit.json"
AUDIT_MEMPALACE = "examples/mempalace.audit.json"

# --- R2: конфигурация прогона (examples/genai_invest_stand.attack.config.json) ---
R2_PATHS = [
    "memrot/catalog/prompts/domain/invest_bank/mem02_global_policy_poisoning",
    "memrot/catalog/prompts/domain/invest_bank/mem01_03_cross_session_semantic_poisoning",
    "memrot/catalog/prompts/domain/invest_bank/auth_tool_direct_bac_injection",
    "memrot/catalog/prompts/domain/invest_bank/framing_diversity",
    "memrot/catalog/prompts/domain/invest_bank/benign_control",
]
R2_TECHNIQUES = ["paraphrase", "roleplay_framing"]

# Измеренные вердикты R2 по группам rule_id (Attack Results, presentation demo).
R2_CONFIRMED_BY_GROUP: Dict[str, Tuple[int, int]] = {   # group -> (CONFIRMED, всего)
    "AUTH-02+TOOL-04+TOOL-05": (9, 9),
    "MEM-01+MEM-03": (12, 27),
    "MEM-02": (1, 21),
    "(untagged)": (0, 9),
}

# --- R1: конфигурация прогона (full demo, Part 1), без аудита ---
R1_BANK_PATHS = [
    "memrot/catalog/prompts/domain/invest_bank/mem02_global_policy_poisoning",
    "memrot/catalog/prompts/domain/invest_bank/auth_tool_direct_bac_injection",
    "memrot/catalog/prompts/domain/invest_bank/benign_control",
]
R1_GENERIC_PATHS = [
    "memrot/catalog/prompts/generic/generic_memory_prompt_injection",
    "memrot/catalog/prompts/generic/generic_sensitive_data_leakage",
    "memrot/catalog/prompts/generic/generic_protected_key_tampering",
    "memrot/catalog/prompts/generic/generic_memory_integrity_violation",
    "memrot/catalog/prompts/generic/generic_bulk_injection_anomaly",
    "memrot/catalog/prompts/generic/generic_tool_output_instruction_injection",
]
# Измеренные вердикты R1: ASR по rule_id и по категории OWASP AMG.
R1_BY_RULE = {"AUTH-02": (9, 9), "TOOL-04": (9, 9), "TOOL-05": (9, 9),
              "MEM-02": (0, 15), "(untagged)": (6, 66)}
R1_BY_AMG = {"tool_output_instruction_injection": (14, 18),
             "protected_key_tampering": (1, 9),
             "memory_prompt_injection": (0, 30),
             "memory_integrity_violation": (0, 9),
             "sensitive_data_leakage": (0, 9),
             "bulk_injection_anomaly": (0, 6),
             "(untagged)": (0, 9)}
R1_TOTAL = (15, 90)
R2_TOTAL = (22, 66)

# Тайминги (wall-clock, сохранённые выводы ноутбуков).
T_AUDIT_S = 1.0            # Stage 1, статический аудит
T_ATTACK_S = 1211.4        # Stage 2, весь прогон R2 целиком
T_PER_VARIANT_S = 873.0 / 66.0   # цикл атаки: 66 вариантов за 14:33


def load_seeds(paths: List[str]):
    return StaticCatalogGenerator(paths).generate()


def expand(seeds, techniques: List[str]):
    """Порядок, в котором LLMMutationGenerator.generate() отдаёт варианты:
    сначала все seed'ы в порядке каталога, затем мутанты, сгруппированные
    по seed'у (keep_seeds=True)."""
    out = list(seeds)
    for s in seeds:
        for t in techniques:
            c = copy.deepcopy(s)
            c.id = f"{s.id}__{t}"
            out.append(c)
    return out


def group_of(v) -> str:
    return "+".join(v.rule_ids) if v.rule_ids else "(untagged)"


def asr_of_group(group: str) -> float:
    conf, total = R2_CONFIRMED_BY_GROUP[group]
    return conf / total if total else 0.0


def discovery_curve(order, budgets: List[int]) -> List[float]:
    """Ожидаемое число CONFIRMED в первых k попытках.

    Индивидуальные вердикты вариантов в сохранённых артефактах агрегированы до
    групп rule_id, поэтому внутри группы принимается равномерное распределение
    успехов (обменяемость вариантов группы). Для группы с ASR=1.0 или 0.0
    значение точное и от допущения не зависит."""
    out = []
    for k in budgets:
        out.append(sum(asr_of_group(group_of(v)) for v in order[:k]))
    return out


def expected_first_success(order) -> float:
    """E[номер первой попытки с CONFIRMED] при том же допущении."""
    exp, p_none = 0.0, 1.0
    for i, v in enumerate(order, 1):
        p = asr_of_group(group_of(v))
        exp += i * p_none * p
        p_none *= (1.0 - p)
    return exp + p_none * (len(order) + 1)


def audit_counts(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    s = doc["summary"]
    cov = {c["metric"]: c["display"] for c in doc["coverage"]}
    fails = sorted({r["rule_id"] for r in doc["control_results"] if r["control_outcome"] == "FAIL"})
    return {
        "findings": len(doc["findings"]),
        "confirmed": s["findings_confirmed"],
        "hypotheses": s["findings_hypotheses"],
        "by_severity": s["findings_by_severity"],
        "controls": s["control_results"],
        "fail_rules": fails,
        "coverage": cov.get("mandatory_control_coverage"),
        "runtime": s["runtime_validation_performed"],
    }


def pct(conf: int, total: int) -> str:
    return f"{conf}/{total} ({100.0 * conf / total:.1f}%)" if total else "n/a (0/0)"


def main() -> None:
    print("=" * 78)
    print("Т1. Статика: что нашёл mcp_audit (offline, runtime_validation_performed=false)")
    print("=" * 78)
    for label, path in (("genai_invest", AUDIT_INVEST), ("MemPalace", AUDIT_MEMPALACE)):
        a = audit_counts(path)
        print(f"\n{label}: находок {a['findings']} "
              f"(static_supported {a['confirmed']}, hypothesis {a['hypotheses']}), "
              f"severity {a['by_severity']}")
        print(f"  контроли: {a['controls']}")
        print(f"  FAIL-правила ({len(a['fail_rules'])}): {', '.join(a['fail_rules'])}")
        print(f"  mandatory_control_coverage: {a['coverage']}; runtime-проверки: {a['runtime']}")

    print()
    print("=" * 78)
    print("Т2. Рукописный (человеческий) слой")
    print("=" * 78)
    seeds_invest = load_seeds(["memrot/catalog/prompts/domain/invest_bank"])
    seeds_mp = load_seeds(["memrot/catalog/prompts/domain/mempalace"])
    seeds_generic = load_seeds(["memrot/catalog/prompts/generic"])
    rules_invest = sorted({r for v in seeds_invest for r in v.rule_ids})
    rules_mp = sorted({r for v in seeds_mp for r in v.rule_ids})
    print(f"seed-вариантов рукописных: invest_bank {len(seeds_invest)}, "
          f"mempalace {len(seeds_mp)}, generic {len(seeds_generic)}, "
          f"итого {len(seeds_invest) + len(seeds_mp) + len(seeds_generic)}")
    print(f"  invest_bank покрывает rule_id: {', '.join(rules_invest)}")
    print(f"  mempalace  покрывает rule_id: {', '.join(rules_mp)}")
    print("  generic: rule_id не заданы (привязка только к таксономии OWASP AMG)")

    print()
    print("=" * 78)
    print("Т3. Динамика: два прогона против одного и того же живого стенда")
    print("=" * 78)
    r1_seeds = load_seeds(R1_BANK_PATHS + R1_GENERIC_PATHS)
    r1_variants = expand(r1_seeds, ["prefix_injection", "persona_override"])
    tagged = [v for v in r1_variants if v.rule_ids]
    untagged_amg = [v for v in r1_variants if not v.rule_ids and v.owasp_amg_category]
    controls = [v for v in r1_variants if not v.rule_ids and not v.owasp_amg_category]
    print(f"R1 (без аудита): {len(r1_seeds)} seed -> {len(r1_variants)} вариантов; "
          f"ASR {pct(*R1_TOTAL)}")
    print(f"   из них привязанных к находкам аудита (rule_id): {len(tagged)}, "
          f"generic: {len(untagged_amg)}, benign-контролей: {len(controls)}")
    r1_tagged_conf = R1_BY_RULE["AUTH-02"][0] + R1_BY_RULE["MEM-02"][0]
    r1_generic_conf = R1_TOTAL[0] - r1_tagged_conf
    print(f"   ASR на привязанных к аудиту: {pct(r1_tagged_conf, len(tagged))}")
    print(f"   ASR на generic:              {pct(r1_generic_conf, len(untagged_amg))}")
    print(f"   ASR на benign-контролях:     {pct(0, len(controls))}  (ложных срабатываний нет)")
    print(f"   критическое семейство AUTH-02+TOOL-04+TOOL-05: {pct(*R1_BY_RULE['AUTH-02'])}")

    r2_seeds = load_seeds(R2_PATHS)
    r2_variants = expand(r2_seeds, R2_TECHNIQUES)
    ranked, lims = select_variants_by_audit(r2_variants, AUDIT_INVEST, mode="ranked")
    print(f"\nR2 (аудит-ранжирование): {len(r2_seeds)} seed -> {len(r2_variants)} вариантов; "
          f"ASR {pct(*R2_TOTAL)}")
    for g, (c, t) in R2_CONFIRMED_BY_GROUP.items():
        print(f"   {g:26s} {pct(c, t)}")
    print(f"   ограничения ранжирования: {lims}")

    print()
    print("=" * 78)
    print("Т4. Абляция: аудит-ранжирование vs тот же прогон без аудита")
    print("=" * 78)
    budgets = [3, 5, 9, 15, 22, 33, 44, 66]
    curve_ranked = discovery_curve(ranked, budgets)
    curve_catalog = discovery_curve(r2_variants, budgets)
    total_conf = R2_TOTAL[0]
    n = len(r2_variants)
    print(f"{'бюджет k':>9} | {'ранжир.':>9} | {'каталог':>9} | {'случайный':>10} | {'выигрыш':>8}")
    for k, a, b in zip(budgets, curve_ranked, curve_catalog):
        rnd = k * total_conf / n
        gain = f"x{a / b:.1f}" if b > 0 else "inf"
        print(f"{k:>9} | {a:>9.1f} | {b:>9.1f} | {rnd:>10.1f} | {gain:>8}")
    print(f"\nE[номер первой успешной попытки]: ранжированный {expected_first_success(ranked):.2f}, "
          f"каталожный {expected_first_success(r2_variants):.2f}, "
          f"случайный {(n + 1) / (total_conf + 1):.2f}")
    print(f"E[время до первого подтверждения] при {T_PER_VARIANT_S:.1f} с/вариант: "
          f"ранжированный {expected_first_success(ranked) * T_PER_VARIANT_S:.0f} с, "
          f"каталожный {expected_first_success(r2_variants) * T_PER_VARIANT_S:.0f} с, "
          f"случайный {(n + 1) / (total_conf + 1) * T_PER_VARIANT_S:.0f} с")
    print(f"\nСтоимость этапов: статический аудит {T_AUDIT_S:.1f} с "
          f"({100.0 * T_AUDIT_S / (T_AUDIT_S + T_ATTACK_S):.2f}% сквозного времени), "
          f"динамический прогон {T_ATTACK_S:.1f} с")

    print()
    print("=" * 78)
    print("Т5. Замыкание словаря: static_path_supported -> runtime_path_observed")
    print("=" * 78)
    a = audit_counts(AUDIT_INVEST)
    runtime_rules = sorted({r for g in R2_CONFIRMED_BY_GROUP
                            for r in g.split("+") if g != "(untagged)"
                            and R2_CONFIRMED_BY_GROUP[g][0] > 0})
    observed = [r for r in runtime_rules if r in a["fail_rules"]]
    not_observed = [r for r in a["fail_rules"] if r not in runtime_rules]
    outside = [r for r in runtime_rules if r not in a["fail_rules"]]
    print(f"FAIL-контролей статики: {len(a['fail_rules'])}")
    print(f"  подтверждено динамикой ({len(observed)}): {', '.join(observed)}")
    print(f"  не воспроизведено в этом прогоне ({len(not_observed)}): {', '.join(not_observed)}")
    print(f"  подтверждено динамикой вне множества FAIL ({len(outside)}): {', '.join(outside) or '—'}")


if __name__ == "__main__":
    main()
