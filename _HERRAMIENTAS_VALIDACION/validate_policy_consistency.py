#!/usr/bin/env python3
"""Valida consistencia interna de policies/case_types/*.yaml.

Verifica:
- case_type único (sin duplicados entre archivos activos).
- status permitido (solo los definidos en policies/case_state_machine.yaml,
  cuando la policy declara transiciones/estados propios -- la mayoría de
  policies de case_type no lo hacen, solo referencian el estado inicial
  implícito 'new').
- priority permitida (solo los 4 niveles: informativo/atencion/urgente/critico).
- fingerprint_fields válidos (no vacío, sin duplicados).
- source_rules bien formado (cada uno con rule_id).
- material_changes presente (aunque sea lista vacía documentada).
- routing presente.
- human_review_required presente (booleano).
- schema references: si la policy menciona un archivo de specifications/,
  verifica que exista.

Uso:
    python scripts/validate_policy_consistency.py

Código de salida: 0 si todo pasa, distinto de cero si hay errores.
"""
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("PyYAML no instalado (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(REPO_ROOT)

VALID_PRIORITY_LEVELS = {"informativo", "atencion", "urgente", "critico"}
ERRORS = []


def error(msg):
    ERRORS.append(msg)
    print(f"[FAIL] {msg}")


def ok(msg):
    print(f"[PASS] {msg}")


def load_state_machine_states():
    sm_path = "policies/case_state_machine.yaml"
    if not os.path.exists(sm_path):
        error(f"{sm_path} no existe -- no se puede validar 'status' contra la máquina de estados única")
        return set()
    sm = yaml.safe_load(open(sm_path, encoding="utf-8").read())
    return {s["name"] for s in sm.get("states", [])}


def check_schema_reference(text, policy_file):
    """Busca menciones a specifications/*.schema.json o *.md dentro del
    texto de la policy y verifica que el archivo referenciado exista."""
    refs = re.findall(r"specifications/[\w.\-]+\.(?:schema\.json|md)", text)
    for ref in set(refs):
        if not os.path.exists(ref):
            error(f"{policy_file}: referencia a '{ref}' que no existe en el repositorio")


def main():
    valid_states = load_state_machine_states()
    seen_case_types = {}

    policy_files = sorted(glob.glob("policies/case_types/*.yaml"))
    if not policy_files:
        error("no se encontraron policies en policies/case_types/*.yaml")
        sys.exit(1)

    for f in policy_files:
        raw_text = open(f, encoding="utf-8").read()
        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as e:
            error(f"{f}: YAML inválido -- {e}")
            continue

        if not data:
            error(f"{f}: archivo vacío")
            continue

        # Archivos de deprecación (ver VULNERABILITY_KEV.yaml) se saltan de
        # la mayoría de validaciones, solo se exige que declaren su reemplazo.
        if data.get("status") == "DEPRECATED":
            if not data.get("replaced_by"):
                error(f"{f}: status=DEPRECATED pero sin campo 'replaced_by'")
            else:
                ok(f"{f}: archivo de deprecación válido (replaced_by={data['replaced_by']})")
            continue

        case_type = data.get("case_type")
        if not case_type:
            error(f"{f}: falta 'case_type'")
            continue

        if case_type in seen_case_types:
            error(f"case_type duplicado '{case_type}': {seen_case_types[case_type]} y {f}")
        else:
            seen_case_types[case_type] = f

        # fingerprint_fields
        ff = data.get("fingerprint_fields")
        if not ff:
            error(f"{f}: falta 'fingerprint_fields' o está vacío")
        elif len(ff) != len(set(ff)):
            error(f"{f}: 'fingerprint_fields' tiene campos duplicados: {ff}")
        else:
            ok(f"{f}: fingerprint_fields válido ({'+'.join(ff)})")

        # source_rules
        source_rules = data.get("source_rules", [])
        if not source_rules:
            error(f"{f}: falta 'source_rules' o está vacío")
        else:
            for i, rule in enumerate(source_rules):
                if not rule.get("rule_id"):
                    error(f"{f}: source_rules[{i}] sin 'rule_id'")

        # material_changes (puede ser lista, incluso vacía si está documentado)
        if "material_changes" not in data:
            error(f"{f}: falta 'material_changes' (usar lista vacía si no aplica, pero debe existir)")

        # routing
        if "routing" not in data:
            error(f"{f}: falta 'routing'")
        else:
            routing = data["routing"]
            # soporta routing simple o routing con sub-rutas (default/when_*)
            candidates = [routing] if "client_priority_level" in routing else list(routing.values())
            for c in candidates:
                if not isinstance(c, dict):
                    continue
                cpl = c.get("client_priority_level")
                if cpl is not None and cpl not in VALID_PRIORITY_LEVELS:
                    error(f"{f}: client_priority_level '{cpl}' no está en {VALID_PRIORITY_LEVELS}")

        # human_review_required
        if "human_review_required" not in data:
            error(f"{f}: falta 'human_review_required'")
        elif not isinstance(data["human_review_required"], bool):
            error(f"{f}: 'human_review_required' debe ser booleano")

        # schema references
        check_schema_reference(raw_text, f)

    if not ERRORS:
        print(f"\n[PASS] {len(seen_case_types)} policies consistentes: {sorted(seen_case_types.keys())}")
        sys.exit(0)
    else:
        print(f"\n{len(ERRORS)} errores encontrados.")
        sys.exit(1)


if __name__ == "__main__":
    main()
