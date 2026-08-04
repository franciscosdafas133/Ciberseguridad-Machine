# _HERRAMIENTAS_VALIDACION — uso técnico, no lectura del proyecto

Esta carpeta no es parte de la lectura recomendada (01 a 06). Contiene los scripts que verifican automáticamente que los schemas, policies y documentos del proyecto son consistentes entre sí — pensados para un desarrollador, no para entender qué es Kriptome.

## Contenido

- `validate_repository.py` — 26 checks de validación: sintaxis de JSON/YAML/XML, contratos cruzados entre schemas, que no queden referencias a nombres retirados, que la máquina de estados sea única, etc.
- `generate_routing_matrix.py` — genera la matriz de routing derivada a partir de las policies de tipos de caso.
- `validate_policy_consistency.py` — validación adicional de consistencia entre policies.
- `.github/workflows/validate-contracts.yml` — ejecuta los mismos checks automáticamente en cada cambio del repositorio.

## Importante: estos scripts esperan la estructura de carpetas ORIGINAL, no esta reorganización

`validate_repository.py` y los demás scripts tienen rutas escritas directamente en el código (`specifications/`, `policies/`, `REGLAS_TUNEADAS/`, `docs/architecture/`, etc.) — la estructura técnica original del repositorio de trabajo, antes de reorganizarse en las carpetas `01_INICIO_AQUI` a `06_COMO_DESPLEGAR` para hacer la lectura más clara.

**Si necesitas ejecutar estas validaciones, hazlo contra el repositorio de trabajo completo** (`Ultimo_kriptome/`, con su estructura original `specifications/`, `policies/`, `procedures/`, `docs/`, `REGLAS_TUNEADAS/`), no contra esta carpeta de entrega reorganizada. Ejecutar `validate_repository.py` desde aquí no encontrará los archivos en sus rutas esperadas y reportará fallos que no reflejan el estado real del proyecto — no es un defecto de los documentos, es que el script busca en las rutas viejas.

El contenido técnico (schemas, policies, reglas) es idéntico entre el repositorio de trabajo y esta entrega — solo cambió cómo están organizadas las carpetas para que un lector nuevo entienda el orden. Todos los fixes y validaciones ya se ejecutaron y confirmaron sobre el repositorio de trabajo antes de generar esta copia reorganizada.
