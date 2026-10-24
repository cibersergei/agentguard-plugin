# GenIA AgentGuard - plugin para Claude Code

Plugin de seguridad de **GenIA AgentGuard** (IMR Consulting) para Claude Code y la pestana Code de Claude Desktop.
Lleva la politica de seguridad de la organizacion al interior de cada sesion del agente:

| Componente | Que hace |
|---|---|
| Skill `agentguard-policy` | Politica en lenguaje concreto: secretos, salida de datos, acciones destructivas, configuracion de Claude, inyeccion de instrucciones, MCP y plugins |
| Skill `agentguard-revisar` | Corre el verificador AgentGuard del equipo, abre el informe local (`~/.agentguard/report.html`) y ayuda a corregir cada problema, con confirmacion del usuario |
| Hook `SessionStart` | Recuerda la politica al iniciar cada sesion |
| Hook `PreToolUse` | Bloquea (`deny`) salida de datos, acceso a secretos, desactivar permisos y cambios a la politica gestionada. Pide confirmacion (`ask`) ante comandos destructivos (salvo borrados de carpetas temporales o de cache) y cambios a `settings.json` o `~/.claude.json`. Desde 0.5.0, si la organizacion lo activa en su baseline (`agentguard_auto_allow`), aprueba (`allow`) sin preguntar los comandos cuyas partes estan todas aprobadas: transferencias a hosts aprobados, borrados temporales y prefijos de comandos de la organizacion |

Para bloquear tambien los cambios a `settings.json` (sin confirmacion), la politica del cliente define la variable
`AGENTGUARD_CONFIG_EDIT=deny` en el bloque `env` de los managed settings. Las plantillas de `templates/` ademas
deniegan `Edit` sobre esos archivos con reglas de permisos.
| `templates/` | Plantillas de managed settings (Windows y macOS) y de `CLAUDE.md` gestionado |

El plugin es la Capa C de AgentGuard. El verificador de endpoint (Capa B) comprueba desde afuera que la politica
esta aplicada y reporta a la consola GenIA AgentGuard. Cada bloqueo indica el control del catalogo que aplica
(por ejemplo `PM-02`).

## Variantes

Claude Code ejecuta el comando de un hook buscandolo en el `PATH` y no permite elegirlo segun el sistema operativo.
Python se llama `python` en Windows y `python3` en macOS, asi que el marketplace publica dos plugins con el mismo contenido:

| Plugin | Sistema | Comando |
|---|---|---|
| `agentguard@imr-agentguard` | Windows | `python` |
| `agentguard-macos@imr-agentguard` | macOS y Linux | `python3` |

Requisito: Python 3.9 o superior en el `PATH`. Los hooks usan solo la biblioteca estandar.

## Instalacion manual (un usuario)

**Claude Desktop (pestana Code), sin linea de comandos:** boton **+** junto al cuadro de mensaje -> **Plugins** ->
**Add plugin**. Agregar el marketplace `cibersergei/agentguard-plugin` e instalar `agentguard` (Windows) o
`agentguard-macos` (macOS).

**Terminal:**

```bash
claude plugin marketplace add cibersergei/agentguard-plugin
```
```bash
claude plugin install agentguard@imr-agentguard
```
En macOS, instalar `agentguard-macos@imr-agentguard`.

## Despliegue gestionado (organizacion)

1. Copiar `templates/managed-settings.windows.json` (o `.macos.json`) y reemplazar los valores `<...>`:
   UUID de la organizacion, dominios aprobados y MCP servers aprobados.
2. Desplegarlo como `managed-settings.json` en `C:\Program Files\ClaudeCode\` (Windows) o
   `/Library/Application Support/ClaudeCode/` (macOS), por Intune, Jamf o GPO.
3. Desplegar `templates/CLAUDE.md` completado en la misma carpeta.

La plantilla fuerza el plugin con `enabledPlugins` y `allowManagedHooksOnly`. Ademas restringe los marketplaces a
este repositorio, deshabilita `bypassPermissions` y el auto mode, y define las reglas `deny` y `ask` de los controles
PM-01, PM-02 y PM-03. En macOS tambien activa el sandbox con allowlist de red (SB-01, SB-02).
Cada clave corresponde a un control del catalogo AgentGuard v1.

## Limitaciones

- Los hooks son una segunda barrera. La barrera dura son las reglas `deny` de la politica gestionada.
- Si el hook no puede leer su entrada, no bloquea (falla abierto), para no frenar el trabajo por un error propio.
- La deteccion de comandos y rutas usa patrones. No reemplaza al sandbox de Claude Code, que en Windows nativo no existe.
- Los mensajes de bloqueo nombran el control, nunca el comando ni el contenido del archivo.

## Desarrollo

La fuente esta en `src/`. Las carpetas `plugins/` se generan con:
```bash
python tools/build.py
```
Tests (biblioteca estandar):
```bash
python -m unittest discover -s tests
```

Version 0.1.0. Copyright 2026 IMR Consulting. Licencia Apache 2.0 (ver `LICENSE` y `NOTICE`).
La licencia no da derechos sobre los nombres "GenIA" ni "AgentGuard".
