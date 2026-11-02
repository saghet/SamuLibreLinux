# 03 — Auditoría Técnica Detallada: Componentes, Funciones y Fallos

**Documento:** `docs/virtual-patching-audit/03-technical-audit.md`  
**Objetivo:** Análisis exhaustivo de implementación a bajo nivel con referencias exactas a líneas de código.

---

## 1. Auditoría de Funciones de Aplicación de Mitigaciones

### 1.1 `enforce_mitigation_helper` ([`src/lib.rs#L1469-L1551`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L1469-L1551))

```rust
fn enforce_mitigation_helper(dry_run: bool, strategy: &MitigationStrategy) -> Result<()> {
    if dry_run { return Ok(()); }
    match strategy {
        MitigationStrategy::NetworkFirewall { rule_name, port, protocol, direction } => {
            #[cfg(not(target_os = "windows"))]
            {
                let dir_flag = if direction == "in" { "-I" } else { "-A" };
                let chain = if direction == "in" { "INPUT" } else { "OUTPUT" };
                let mut cmd = Command::new("iptables");
                // ...
                let _ = cmd.output(); // <-- DEFECTO CRÍTICO: Error descartado
            }
            info!("Regla de firewall {} aplicada.", rule_name);
        }
        MitigationStrategy::BehavioralBlock { target_process, forbidden_call } => {
            // <-- DEFECTO CRÍTICO: Función simulada, solo log
            info!("Bloqueo de comportamiento activo para {} ({})", target_process, forbidden_call);
        }
        MitigationStrategy::KernelSysctlHardening { parameter, safe_value, .. } => {
            #[cfg(target_os = "linux")]
            {
                let path = format!("/proc/sys/{}", parameter.replace('.', "/"));
                let _ = std::fs::write(&path, safe_value); // <-- DEFECTO CRÍTICO: Falla sin root
            }
            info!("Parámetro de kernel {} endurecido a {}.", parameter, safe_value);
        }
        // ...
    }
    Ok(())
}
```

#### Análisis Técnico de Fallos:
1. **Línea 1505 (`let _ = cmd.output();`):**
   - Si `samulibre` se ejecuta sin privilegios de `root` o sin la capacidad `CAP_NET_ADMIN`, el comando `iptables` falla con código de retorno 1 (`Permission denied (you must be root)`).
   - El código descarta deliberadamente el `Result` (`let _ =`). La función retorna `Ok(())` incondicionalmente.
   - En la línea 1507 se imprime en el log: `"Regla de firewall SamuLibre_... aplicada."`, induciendo a un falso positivo operativo.
2. **Líneas 1529-1531 (`BehavioralBlock`):**
   - No hay implementación funcional. No se utiliza eBPF LSM, ni seccomp-bpf, ni `prctl(PR_SET_SECCOMP)`, ni se suspende ningún proceso.
   - Si un atacante ejecuta `pkexec` aprovechando CVE-2021-4034, el exploit se ejecuta con éxito total mientras SamuLibre muestra que el ataque fue "mitigado por el Centinela".
3. **Líneas 1533-1538 (`KernelSysctlHardening`):**
   - La escritura directa en `/proc/sys/...` requiere `root` (`EACCES`). Al usar `let _ = std::fs::write(...)`, si la operación falla, no se lanza ningún error.
   - Peor aún: **los cambios en `/proc/sys` son volátiles**. No se crea ningún archivo en `/etc/sysctl.d/99-samulibre.conf`. Al reiniciar la máquina, cualquier sysctl modificado vuelve a su valor por omisión sin que el antivirus lo detecte ni lo restablezca al arrancar.

---

### 1.2 `revert_mitigation_helper` ([`src/lib.rs#L1554-L1617`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L1554-L1617))

```rust
fn revert_mitigation_helper(dry_run: bool, strategy: &MitigationStrategy) -> Result<()> {
    // ...
    match strategy {
        MitigationStrategy::NetworkFirewall { rule_name, .. } => {
            #[cfg(not(target_os = "windows"))]
            {
                let _ = Command::new("iptables").args(["-D", "INPUT", "-m", "comment", "--comment", rule_name, "-j", "DROP"]).output();
            }
        }
        MitigationStrategy::KernelSysctlHardening { parameter, revert_value, .. } => {
            #[cfg(target_os = "linux")]
            {
                let path = format!("/proc/sys/{}", parameter.replace('.', "/"));
                let _ = std::fs::write(&path, revert_value);
            }
        }
        // ...
    }
    Ok(())
}
```

#### Análisis Técnico de Fallos:
1. **Suposición fija de cadena `INPUT`:** La regla de reversión en `iptables` asume que la regla estaba en `INPUT`. Si la regla original se configuró en `OUTPUT` (`direction == "out"`), el comando `-D INPUT` falla y la regla en `OUTPUT` queda huérfana para siempre.
2. **Falta de idempotencia y validación:** No verifica si la regla existe antes de eliminarla ni valida si el parámetro sysctl realmente fue restaurado.

---

## 2. Auditoría del Monitor de KBs y Detección de Parches Nativos

### 2.1 `get_installed_kbs` ([`src/lib.rs#L511-L536`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L511-L536))

```rust
pub fn get_installed_kbs(&self) -> HashSet<String> {
    let mut installed = HashSet::new();
    #[cfg(target_os = "windows")]
    {
        // PowerShell Get-HotFix ...
    }
    installed
}
```

#### Análisis Técnico del Fallo:
- En Linux, este método **retorna siempre un `HashSet` vacío (`HashSet::new()`)**.
- En el método `run_daily_kb_verification()` y en `get_kb_monitor_status()`, se calcula:
  ```rust
  let pending_count = self.monitored_kbs.iter().filter(|k| !installed.contains(&k.kb_id.to_uppercase())).count();
  ```
- **Consecuencia directa:** Como `installed` siempre está vacío en Linux, **TODOS los boletines del catálogo (`USN-5252-1`, `RHSA-2022:0267`) se reportan siempre como "PENDIENTE - REQUIERE VIRTUAL PATCH"**, incluso cuando el paquete correspondiente ya está actualizado e instalado en el sistema operativo.

---

### 2.2 `check_cve_native_mitigation` ([`src/lib.rs#L1404-L1465`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-patcher/src/lib.rs#L1404-L1465))

```rust
match cve {
    "CVE-2021-4034" => {
        if !std::path::Path::new("/usr/bin/pkexec").exists() {
            return Some((false, "Inmune: pkexec no se encuentra instalado en este sistema.".to_string()));
        } else {
            return Some((true, "Mitigación activa y paquete de seguridad USN-5252 verificado en el sistema.".to_string()));
        }
    }
    // ...
}
```

#### Análisis Técnico del Fallo:
- Para `CVE-2021-4034` (PwnKit), si el archivo `/usr/bin/pkexec` existe, el código asume ciegamente: `"Mitigación activa y paquete de seguridad USN-5252 verificado"`.
- **Falso Negativo Crítico:** El código **no comprueba la versión del binario ni del paquete polkit**. Si el sistema es un Ubuntu 20.04 sin actualizar con un `pkexec` vulnerable de 2021, SamuLibre le dirá al usuario que está "Corregido nativamente" basándose únicamente en que el archivo existe en el disco.

---

## 3. Auditoría del Analizador con Inteligencia Artificial (`samulibre-ai`)

### 3.1 `analyze_raw_text` ([`crates/samulibre-ai/src/lib.rs#L128-L202`](file:///home/saghet/Documents/SamulibreLinux/crates/samulibre-ai/src/lib.rs#L128-L202))

Cuando el usuario solicita auditar o sintetizar una regla para un boletín en Linux, la IA entra en la función `synthesize_mitigation`:

```rust
// Caso por omisión en crates/samulibre-ai/src/lib.rs:
let strategy = MitigationStrategy::BehavioralBlock {
    target_process: "powershell.exe".to_string(),
    forbidden_call: format!("-enc *{}", kb),
};
```

#### Evidencia Obtenida en Disco ([`data/cve_rules/dynamic_CVE_2021_4034.json`](file:///home/saghet/Documents/SamulibreLinux/data/cve_rules/dynamic_CVE_2021_4034.json)):
```json
{
  "id": "VP-AI-CVE_2021_4034",
  "cve": "CVE-2021-4034",
  "title": "[IA Patch] Ubuntu & Debian Security Notice: Polkit pkexec (PwnKit)",
  "target_component": "Windows Subsystem Generic",
  "strategy": {
    "BehavioralBlock": {
      "target_process": "powershell.exe",
      "forbidden_call": "-enc *KBUSN-5252-1"
    }
  }
}
```

**Diagnóstico:** Para una vulnerabilidad local de Linux (`pkexec`), la IA genera una regla que bloquea argumentos codificados de PowerShell en Windows. En Linux, esta regla es completamente absurda e inoperante.

---

## 4. Matriz de Cobertura de Vulnerabilidades Linux Actuales

| CVE | Componente | Tipo de Mitigación Real | ¿Funciona en SamuLibre? | Justificación Técnica |
|---|---|---|:---:|---|
| **CVE-2022-0185** | Kernel user namespaces | Deshabilitar unprivileged userns (`sysctl`) | ⚠️ **Condicional** | Solo si SamuLibre se ejecuta como `root`. Si se ejecuta como usuario regular, falla en silencio. |
| **CVE-2020-0001** | KASLR / Punteros Kernel | sysctl `kptr_restrict=2` | ⚠️ **Condicional** | Solo si SamuLibre es `root`. En la base oficial NVD este CVE corresponde a Android Media Framework, no a Linux KASLR. |
| **CVE-2016-5195** | Dirty COW / ptrace | sysctl `yama.ptrace_scope=2` | ⚠️ **Condicional** | Solo como root. Yama no mitiga Dirty COW (condición de carrera de COW de memoria anónima). Es una asociación técnica errónea. |
| **CVE-2019-18282** | VFS FIFOs en `/tmp` | sysctl `fs.protected_fifos=2` | ⚠️ **Condicional** | Mitigación válida de VFS pero solo aplicable como root. |
| **CVE-2021-4034** | Polkit pkexec (PwnKit) | `BehavioralBlock` | ❌ **NO FUNCIONA** | `BehavioralBlock` es un log vacío; además la IA generó bloqueo de `powershell.exe`. |
| **CVE-2024-1086** | Linux Netfilter nf_tables | No contemplado | ❌ **NO EXISTE** | No existe regla en el catálogo. |
| **CVE-2024-6387** | OpenSSH regreSSHion | No contemplado | ❌ **NO EXISTE** | No existe regla en el catálogo. |
| **CVE-2024-21626** | runc container breakout | No contemplado | ❌ **NO EXISTE** | No existe regla en el catálogo. |
| **CVE-2023-32233** | Netfilter nf_tables LPE | No contemplado | ❌ **NO EXISTE** | No existe regla en el catálogo. |
