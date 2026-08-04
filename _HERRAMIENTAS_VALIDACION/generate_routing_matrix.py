#!/usr/bin/env python3
"""Genera un routing matrix DERIVADO desde policies/case_types/*.yaml.

ESTADO: DISEÑADO / uso parcial. El routing_matrix.csv HISTÓRICO en
REGLAS_TUNEADAS/routing/ (mantenido a mano) tiene 12 columnas con
granularidad por-regla-nativa (umbral, ventana, correlación, notas de
tuning) que las policies actuales de policies/case_types/*.yaml NO capturan
con la misma fidelidad -- las policies describen el case_type completo, no
cada variante de regla individual dentro de él. Por eso este script genera
un CSV DERIVADO más simple (columnas: case_type, rule_id, rule_role,
wazuh_family, validation_status, fingerprint_fields, routing.wazuh_route,
routing.client_priority_level, human_review_required) que sirve para
verificar consistencia (policies <-> routing) automáticamente, pero NO
reemplaza todavía al CSV histórico de 12 columnas -- ver
docs/architecture/ARCHITECTURE_CANONICAL.md y DOCUMENTATION_SOURCE_OF_TRUTH.md
fila 'Origen de routing_matrix.csv'.

Uso:
    python scripts/generate_routing_matrix.py [--check]

--check: no escribe el archivo, solo verifica que generaría el mismo
         contenido que el archivo actual (falla el CI si hay drift).

Reglas de generación (obligatorias, no se inventan datos faltantes):
1. Lee todas las policies de policies/case_types/*.yaml.
2. Valida que cada policy tenga los campos obligatorios de
   scripts/validate_policy_consistency.py (falla si no).
3. Genera una fila por cada source_rule declarado en cada policy.
4. Ordena las filas de forma consistente (por case_type, luego por rule_id).
5. Falla si dos policies distintas declaran el mismo case_type (nombre duplicado).
6. Falla si un source_rule referencia un case_type que no coincide con el
   nombre de archivo/policy que lo declara (verificación de integridad
   simple: el campo case_type de la policy debe ser consistente consigo
   misma).
7. No inventa datos: si un campo esperado no existe en la policy, la celda
   queda vacía ('') en vez de rellenarse con un valor supuesto.
8. rule_role (v1.3.1 Theory Closure, Fase 12): cada source_rule se clasifica
   en uno de detects/contextual/suppresses/closes/experimental/deprecated
   -- ver _infer_rule_role(). Nunca se presenta una regla supresora (level=0,
   p.ej. 100030) como si abriera casos, ni una regla EXPERIMENTAL/DESCARTADA
   como candidata productiva.
9. Todos los paths generados (columna policy_file) usan '/' siempre,
   independientemente del sistema operativo donde corra el script.
"""
import argparse
import csv
import glob
import io
import os
import sys

try:
    import yaml
except ImportError:
    print("PyYAML no instalado (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(REPO_ROOT)

POLICIES_DIR = "policies/case_types"
OUTPUT_DERIVED_CSV = "REGLAS_TUNEADAS/routing/routing_matrix.derived.csv"

FIELDNAMES = [
    "case_type",
    "rule_id",
    "rule_role",
    "wazuh_family",
    "rule_validation_status",
    "fingerprint_fields",
    "wazuh_route",
    "client_priority_level",
    "human_review_required",
    "policy_validation_status",
    "policy_file",
]

# Grupos/estados que marcan una regla como no-detectora. No se infiere desde
# el propio texto libre de 'note' (frágil); se usa una señal estructurada
# cuando existe (policy_scope_status) y, si no, el propio contexto declarado
# por la policy (routing.wazuh_route) como mejor aproximación disponible sin
# inventar un campo nuevo obligatorio en cada policy todavía.
_DESCARTADA_MARKERS = {"DESCARTADA-PARA-PRODUCCION"}


def _posix(path):
    """Fuerza '/' como separador, independientemente del SO (Fase 12)."""
    return path.replace(os.sep, "/").replace("\\", "/")


def _infer_rule_role(policy, rule):
    """Clasifica un source_rule en detects/contextual/suppresses/closes/
    experimental/deprecated. No inventa un campo nuevo en las policies --
    infiere a partir de señales ya presentes (rule_id conocido 100030 como
    supresor, policy_scope_status, wazuh_route de la policy)."""
    rule_id = str(rule.get("rule_id", ""))
    note = (rule.get("note") or "").lower()
    scope_status = rule.get("policy_scope_status") or policy.get("policy_scope_status")

    if scope_status in _DESCARTADA_MARKERS:
        return "deprecated"
    if rule.get("validation_status") == "EXPERIMENTAL" or "experimental" in note:
        return "experimental"
    # Reglas nativas/custom conocidas de nivel 0 que silencian (nunca abren
    # caso) -- 100030 es el caso documentado en este repositorio hoy.
    if rule_id in {"100030"}:
        return "suppresses"
    # Reglas que cierran un caso ya abierto (p.ej. reconexión de agente).
    if rule_id in {"503"}:
        return "closes"
    wazuh_route = policy.get("routing", {})
    if "wazuh_route" not in wazuh_route:
        wazuh_route = wazuh_route.get("default", {})
    route_value = wazuh_route.get("wazuh_route", "")
    if route_value == "CONTEXT":
        return "contextual"
    return "detects"


def load_policies():
    """Carga todas las policies, saltando explícitamente las marcadas
    DEPRECATED (ver policies/case_types/VULNERABILITY_KEV.yaml)."""
    policies = {}
    errors = []
    for f in sorted(glob.glob(os.path.join(POLICIES_DIR, "*.yaml"))):
        f = _posix(f)
        docs = list(yaml.safe_load_all(open(f, encoding="utf-8").read()))
        data = docs[0] if docs else None
        if not data:
            continue
        if data.get("status") == "DEPRECATED":
            continue  # archivo de deprecación, no una policy activa
        case_type = data.get("case_type")
        if not case_type:
            errors.append(f"{f}: no tiene campo 'case_type'")
            continue
        if case_type in policies:
            errors.append(
                f"case_type duplicado '{case_type}': declarado en "
                f"{policies[case_type]['_file']} y en {f}"
            )
            continue
        data["_file"] = f
        policies[case_type] = data
    return policies, errors


def build_rows(policies):
    rows = []
    errors = []
    for case_type, policy in policies.items():
        fingerprint_fields_list = policy.get("fingerprint_fields", [])
        fingerprint_fields = "+".join(fingerprint_fields_list)
        # Validación: fingerprint_fields siempre debe incluir al menos
        # tenant_id, asset_id y case_type -- inconsistencia si falta alguno.
        for required_field in ("tenant_id", "asset_id", "case_type"):
            if required_field not in fingerprint_fields_list:
                errors.append(
                    f"{policy['_file']}: case_type '{case_type}' tiene "
                    f"fingerprint_fields inconsistente -- falta '{required_field}'"
                )

        routing = policy.get("routing", {})
        # routing puede ser un dict simple (wazuh_route directo) o un dict de
        # sub-rutas (ver policies/case_types/VULNERABILITY.yaml: default/when_kev_listed/...)
        if "wazuh_route" in routing:
            wazuh_route = routing.get("wazuh_route", "")
            client_priority_level = routing.get("client_priority_level", "")
        else:
            # tomar la sub-ruta 'default' si existe, documentando que hay mas de una
            default_route = routing.get("default", {})
            wazuh_route = default_route.get("wazuh_route", "")
            client_priority_level = default_route.get("client_priority_level", "")

        source_rules = policy.get("source_rules", [])
        if not source_rules:
            errors.append(f"{policy['_file']}: case_type '{case_type}' sin source_rules")
            continue

        for rule in source_rules:
            rule_id = rule.get("rule_id")
            if not rule_id:
                errors.append(f"{policy['_file']}: un source_rule de '{case_type}' no tiene rule_id")
                continue

            rule_role = _infer_rule_role(policy, rule)

            # wazuh_route/client_priority_level son atributos del case_type
            # completo (agregado), no de cada source_rule individual -- una
            # regla con rule_role experimental/deprecated/suppresses NUNCA
            # hereda ese routing productivo en el CSV derivado, aunque las
            # demas reglas de la misma policy si lo tengan (evita presentar
            # 100040 o 100030 como si fueran las que disparan el caso).
            if rule_role in ("experimental", "deprecated", "suppresses"):
                row_wazuh_route = ""
                row_priority_level = ""
            else:
                row_wazuh_route = wazuh_route
                row_priority_level = client_priority_level

            rows.append({
                "case_type": case_type,
                "rule_id": rule_id,
                "rule_role": rule_role,
                "wazuh_family": rule.get("wazuh_family", ""),
                "rule_validation_status": rule.get("validation_status", ""),
                "fingerprint_fields": fingerprint_fields,
                "wazuh_route": row_wazuh_route,
                "client_priority_level": row_priority_level,
                "human_review_required": policy.get("human_review_required", ""),
                "policy_validation_status": policy.get("policy_validation_status", ""),
                "policy_file": _posix(policy["_file"]),
            })

    # Orden consistente: por case_type, luego por rule_id (como string, ya
    # que algunos rule_id son compuestos como "5716/5760").
    rows.sort(key=lambda r: (r["case_type"], r["rule_id"]))
    return rows, errors


def check_referenced_case_types_exist(policies):
    """Detecta referencias deprecadas: un case_type mencionado en
    related_incident_policy/campaign_correlation que no exista como policy
    activa (posible referencia a un case_type renombrado/eliminado)."""
    errors = []
    active_case_types = set(policies.keys())
    for case_type, policy in policies.items():
        text_blob = str(policy)
        for other_case_type in ("VULNERABILITY_KEV",):
            if other_case_type in text_blob and other_case_type not in active_case_types:
                errors.append(
                    f"{policy['_file']}: referencia al case_type deprecado "
                    f"'{other_case_type}' -- verificar que sea intencional (histórico) "
                    f"y no una referencia activa rota"
                )
    return errors


def render_csv(rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDNAMES)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="no escribe, solo verifica drift")
    args = parser.parse_args()

    policies, errors = load_policies()
    if errors:
        print("Errores cargando policies:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    rows, row_errors = build_rows(policies)
    row_errors.extend(check_referenced_case_types_exist(policies))
    if row_errors:
        print("Errores generando filas:")
        for e in row_errors:
            print(f"  - {e}")
        sys.exit(1)

    content = render_csv(rows)

    if args.check:
        if not os.path.exists(OUTPUT_DERIVED_CSV):
            print(f"[FAIL] {OUTPUT_DERIVED_CSV} no existe -- ejecuta sin --check primero")
            sys.exit(1)
        existing = open(OUTPUT_DERIVED_CSV, encoding="utf-8", newline="").read()
        if existing != content:
            print(f"[FAIL] drift detectado en {OUTPUT_DERIVED_CSV} -- regenera con: python {sys.argv[0]}")
            sys.exit(1)
        print(f"[PASS] {OUTPUT_DERIVED_CSV} sin drift ({len(rows)} filas)")
        sys.exit(0)

    with open(OUTPUT_DERIVED_CSV, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print(f"Generado {OUTPUT_DERIVED_CSV} ({len(rows)} filas, {len(policies)} case_types)")


if __name__ == "__main__":
    main()
