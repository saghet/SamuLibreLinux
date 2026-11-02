# 06 — Estudio de Mercado y Análisis Comparativo de Mejores Prácticas

**Documento:** `docs/virtual-patching-audit/06-market-research.md`  
**Objetivo:** Comparar la aproximación de SamuLibre frente a soluciones industriales líderes en el ecosistema Linux y definir una propuesta de valor técnica sólida.

---

## 1. Desambiguación Conceptual Obligatoria

En la industria de la ciberseguridad, con frecuencia se confunden siete disciplinas distintas. Para un desarrollo profesional en Linux, es imprescindible diferenciarlas:

| Disciplina | ¿Qué es? | Tecnologías Representativas | ¿Es lo que hace SamuLibre hoy? |
|---|---|---|:---:|
| **1. Virtual Patching (Parchado Virtual)** | Reglas de intercepción en línea que inspeccionan tráfico o llamadas para bloquear el payload del exploit sin modificar el binario vulnerable ni reiniciar el servicio. | ModSecurity, Coraza, Suricata, Trend Micro Deep Security, eBPF LSM filters. | ❌ No (solo modifica sysctls y emite logs). |
| **2. Live Kernel Patching** | Reemplazo atómico de código binario en caliente dentro de la memoria del kernel Linux mediante redirección de funciones `ftrace`. | TuxCare KernelCare Enterprise, Oracle Ksplice, Red Hat kpatch, SUSE kGraft. | ❌ No (SamuLibre no compila módulos de kernel ni ftrace). |
| **3. Vulnerability Management** | Inventario de paquetes, escaneo de versiones y correlación con bases CVE para reportar brechas. | Qualys VMDR, Tenable Nessus, Rapid7 InsightVM, OpenVAS. | ⚠️ Parcial (solo evalúa 5 CVEs estáticos). |
| **4. Patch Management** | Descarga, prueba y aplicación de parches reales actualizando paquetes del sistema operativo. | `apt-get upgrade`, `dnf update`, Red Hat Satellite, Canonical Landscape. | ❌ No (tarea del gestor de paquetes de la distro). |
| **5. Web Application Firewall (WAF)** | Inspección L7 de peticiones HTTP/HTTPS para bloquear inyecciones SQL, XSS, RCE y traversal. | ModSecurity CRS, Cloudflare WAF, AWS WAF, Coraza WAF. | ❌ No contemplado en endpoints de escritorio. |
| **6. Intrusion Detection / Prevention (IDS/IPS)** | Análisis de firmas y anomalías de red para alertar o descartar paquetes maliciosos. | Suricata, Snort, Zeek. | ❌ No integrado. |
| **7. System Hardening** | Configuración restrictiva de parámetros del sistema operativo (sysctl, permisos, políticas PAM) para reducir la superficie de ataque. | OpenSCAP, Lynis, CIS Benchmarks, Ansible Lockdown. | ✔ **Sí (es lo que realmente hace SamuLibre hoy).** |

---

## 2. Matriz Comparativa Frente a Soluciones de la Industria

| Solución | Mecanismo de Mitigación | Cobertura en Linux | Impacto en Rendimiento | ¿Requiere Reinicio? | Licencia / Costo |
|---|---|---|:---:|:---:|---|
| **SamuLibre Patcher (Actual)** | Escritura volátil en `/proc/sys/` + logs vacíos | 5 CVEs históricos | Nulo (< 0.01%) | No (pero se pierde al reiniciar) | **Open Source / Libre** |
| **TuxCare KernelCare** | Inyección de parches binarios en memoria mediante módulos de kernel | Más de 5,000 CVEs de kernel | Muy bajo (< 1%) | **Cero reinicio** | Comercial corporativo por nodo |
| **Red Hat Insights** | Diagnóstico de configuración, paquetes desactualizados y playbooks Ansible | RHEL 7, 8, 9, 10 | Bajo (escaneo periódico) | Requiere parche real | Incluido en suscripción RHEL |
| **Wazuh Agent** | Auditoría FIM, detección de rootkits, inventario de vulnerabilidades (OVAL) | Todas las distros Linux | Medio (2-5% CPU) | No mitiga (solo alerta) | **Open Source (GPLv2)** |
| **Suricata IPS** | Inspección de paquetes L3/L4/L7 con descarte de exploits en red (NFQUEUE) | Universal en Linux | Medio a Alto según tráfico | **Cero reinicio** | **Open Source (GPLv2)** |
| **ModSecurity / Coraza** | Inspección de payloads HTTP frente a CVEs de aplicaciones web (OWASP CRS) | Apache, Nginx, Caddy | Variable según peticiones | **Cero reinicio** | **Open Source (Apache 2.0)** |

---

## 3. Propuesta de Valor Diferenciada para SamuLibre Linux

SamuLibre no debe competir con herramientas de Live Kernel Patching como KernelCare (que requieren compilar parches para cientos de builds de kernel específicos), ni limitarse a un escáner pasivo como Nessus.

La oportunidad estratégica para SamuLibre es consolidarse como un **EDR y Motor de Parchado Virtual Autónomo Híbrido en Espacio de Usuario y Kernel Ligero**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   SAMULIBRE VIRTUAL PATCHING V2                        │
├──────────────────────────────────┬─────────────────────────────────────┤
│ 1. Capa de Red (Netfilter/nft):  │ Bloqueo inmediato de paquetes en L4 │
│    Descarta tráfico a puertos    │ explotando CVEs de servicios        │
│    vulnerables sin apagar la app │ expuestos (ej. SSH, RDP, Samba).    │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 2. Capa de Sistema (eBPF/LSM):   │ Intercepción de llamadas execveat / │
│    Bloqueo de argumentos         │ namespaces ante exploits LPE        │
│    maliciosos de exploits        │ conocidos (ej. PwnKit, Looney).     │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 3. Capa de Hardening Persistente:│ Aplicación de sysctls en            │
│    Persistencia en /etc/sysctl.d │ /etc/sysctl.d/ con verificación     │
│    y verificación de integridad  │ continua de estado.                 │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 4. Threat Feeds Dinámicos:       │ Ingesta automática de CISA KEV,     │
│    Actualizaciones en tiempo     │ OSV y Advisories de distros         │
│    real sin recompilar el binario│ (USN, RHSA, Arch Security).         │
└──────────────────────────────────┴─────────────────────────────────────┘
```

Esta arquitectura ofrece:
1. **Verdadero Virtual Patching:** Neutraliza exploits en la red y en el sistema de llamadas sin tocar el código fuente de las aplicaciones.
2. **Zero-Cloud Mandate:** Funciona 100% offline con firmas locales cacheadas.
3. **Cero Falsa Sensación:** No reporta nada como protegido a menos que el filtro nftables o la sonda eBPF esté verificada y activa.
