# POLÍTICA DE PRIVACIDAD Y SOBERANÍA DE DATOS (PRIVACY.MD)
## SamuLibre Linux EDR & Antivirus
**Fecha de Vigencia:** Noviembre 2026  
**Versión:** 2.0 (Fase I: Privacidad por Diseño y Soberanía Local)  

---

## 1. PRINCIPIO FUNDAMENTAL: PRIVACIDAD POR DISEÑO Y POR DEFECTO

En **SamuLibre Linux**, sostenemos que **la seguridad nunca debe comprometer la privacidad del usuario ni la soberanía de los datos**.

A diferencia de la mayoría de los antivirus y agentes EDR comerciales que transmiten metadatos de archivos, rutas de directorios, nombres de usuario y binarios sospechosos a nubes corporativas centralizadas, SamuLibre opera bajo el principio de **Cero Telemetría y Cero Dependencia en la Nube (Zero-Cloud Mandate)**.

---

## 2. QUÉ DATOS RECOPILA Y PROCESA SAMULIBRE

| Categoría de Datos | Dónde se Procesa | Dónde se Almacena | ¿Se Transmite a Terceros? |
| :--- | :---: | :---: | :---: |
| **Contenido de Archivos Escaneados** | Memoria RAM local (y VRAM local) | No se persiste (solo en cuarentena local si es malware) | **NUNCA** |
| **Hashes Criptográficos (SHA-256)** | CPU Host local | Base de datos SQLite local (`events.db`) | **NUNCA** |
| **Eventos EDR y Auditoría VFS** | Demonio local (`samulibred`) | Base de datos SQLite local (`/var/lib/samulibre/events.db`) | **NUNCA** |
| **Rutas de Archivos y Nombres de Usuario**| Sistema local | Base de datos SQLite local (con permisos `0600`) | **NUNCA** |
| **Telemetría Térmica y de Hardware** | Driver local (NVML / Sysfs) | Memoria volátil del demonio | **NUNCA** |
| **Identificadores de Dispositivo / UUID** | Host local | No se generan perfiles de rastreo | **NUNCA** |

---

## 3. COMUNICACIONES DE RED PERMITIDAS

SamuLibre no realiza conexiones salientes silenciosas. Las únicas operaciones de red posibles son **iniciadas de forma explícita y transparente**:
1. **Actualización de Base de Datos de Amenazas (Opcional):**
   - Cuando el usuario o administrador solicita actualizar firmas, el sistema descarga listas de IoCs y reglas YARA firmadas mediante HTTPS desde servidores oficiales de la comunidad o espejos configurados.
   - En esta petición **no se transmite ninguna información sobre los archivos existentes en la máquina del usuario**.
2. **Módulo VPN Seguro (Opcional):**
   - Si el usuario activa voluntariamente el túnel WireGuard/Tor de `samulibre-vpn`, el tráfico se enruta de forma cifrada a través del nodo seleccionado por el usuario, sin registro de actividad (*No-Logs Policy*).

---

## 4. CUMPLIMIENTO REGULATORIO INTERNACIONAL

La arquitectura local de SamuLibre cumple por diseño (*Privacy by Design*) con las regulaciones de protección de datos más estrictas del mundo:
- **GDPR / RGPD (Reglamento General de Protección de Datos de la Unión Europea):** Cumplimiento automático al no existir transferencia internacional de datos personales ni perfilado de usuarios.
- **Esquema Nacional de Seguridad (ENS - España) & NIS2:** Adecuado para instalaciones en infraestructuras críticas y organismos gubernamentales con requisitos de soberanía estricta.
- **HIPAA & PCI-DSS:** Apto para entornos que procesan datos de salud o tarjetas de pago sin riesgo de exfiltración accidental por parte del agente antivirus.

---

## 5. CONTACTO EN MATERIA DE PRIVACIDAD

Para cualquier consulta sobre nuestra arquitectura de privacidad y soberanía de datos:  
📧 **`privacy@samulibre.org`**
