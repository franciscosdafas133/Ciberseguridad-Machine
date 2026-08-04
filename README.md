# Kriptome MiniSOC — Documentación oficial y reglas tuneadas

Este repositorio contiene la entrega final del diseño de Kriptome MiniSOC: la documentación oficial del proyecto y el paquete de reglas Wazuh ya ajustadas ("tuneadas") y corregidas.

## Documentación oficial (leer en este orden)

| # | Documento | Contenido |
|---|---|---|
| 0 | `0. Indice.docx` | Guía de lectura de esta entrega. |
| 1 | `1. Vision y Alcance del Proyecto.docx` | Qué es Kriptome, qué se entrega, qué está listo y qué falta. |
| 2 | `2. Flujo Completo del Sistema.docx` | El recorrido de un evento de seguridad de principio a fin. |
| 3 | `3. Contratos de Datos.docx` | Qué información maneja el sistema en cada etapa. |
| 4 | `4. Reglas de Negocio.docx` | Tipos de caso, estados, fórmula de riesgo, procedimientos. |
| 5 | `5. Reglas Tecnicas de Wazuh.docx` | Detalle de las reglas de detección y sus correcciones. |
| 6 | `6. Guia de Despliegue e Implementacion.docx` | Camino paso a paso hacia un sistema funcionando. |

## Reglas tuneadas (técnico)

- **`Reglas_Tecnicas_Wazuh/`** — el ruleset de Wazuh listo para desplegar: reglas personalizadas, configuración del servidor, listas, datos de prueba.
- **`_HERRAMIENTAS_VALIDACION/`** — scripts que verifican automáticamente la consistencia del proyecto.

## Estado del proyecto

Esta es la **especificación completa** de Kriptome MiniSOC (contratos de datos, reglas de negocio, reglas técnicas de detección), verificada y corregida. **No es el sistema funcionando todavía** — ver el documento 1 para el detalle exacto de qué está implementado y qué queda pendiente.
