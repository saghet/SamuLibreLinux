# ACUERDO DE LICENCIA DE COLABORADOR (CONTRIBUTOR LICENSE AGREEMENT - CLA)
## SamuLibre Linux Open Source Project
**Versión:** 2.0 (Edición 2026)  
**Entidad Administradora:** SamuLibre Security Team (`cla@samulibre.org`)  

---

## 1. INTRODUCCIÓN Y PROPÓSITO DEL ACUERDO

Gracias por tu interés en contribuir a **SamuLibre Linux** ("el Proyecto").

Para proteger a los usuarios de la versión de software libre, preservar la integridad legal de la base de código y permitir que el proyecto opere un **modelo de licenciamiento dual sostenible**, necesitamos que todos los colaboradores acepten este Acuerdo de Licencia de Colaborador (CLA).

> [!NOTE]
> **Lo que este acuerdo significa para ti:**
> 1. **Tú conservas la titularidad de los derechos de autor (Copyright) sobre tu código.** Este acuerdo NO te exige ceder ni transferir la propiedad de tu trabajo.
> 2. **Tú otorgas al Proyecto una licencia no exclusiva, perpetua y mundial** para distribuir tus contribuciones tanto bajo la licencia comunitaria de código abierto (**GPL-3.0-or-later**) como bajo **licencias comerciales alternativas** a empresas y fabricantes OEM.
> 3. **Se preserva tu atribución:** Tu nombre y autoría permanecerán registrados en el historial de Git y en la documentación del proyecto.

---

## 2. DEFINICIONES

- **"Colaborador" o "Tú":** La persona física o entidad jurídica que ostenta los derechos de autor sobre la Contribución y presenta este acuerdo.
- **"Contribución":** Cualquier código fuente, parche, prueba, documentación o material enviado al Proyecto mediante Pull Requests, commits en Git, issues o parches de correo electrónico.
- **"El Proyecto":** El proyecto SamuLibre Linux administrado por el SamuLibre Security Team y sus sucesores autorizados.

---

## 3. CONCESIÓN DE LICENCIA DE DERECHOS DE AUTOR (COPYRIGHT GRANT)

Sujeto a los términos y condiciones de este Acuerdo, el Colaborador otorga por el presente al Proyecto y a los administradores de SamuLibre una **licencia de derechos de autor no exclusiva, perpetua, irrevocable, mundial, libre de regalías y sublicenciable** para:
1. Reproducir, preparar obras derivadas, exhibir públicamente, ejecutar públicamente y distribuir la Contribución y dichas obras derivadas.
2. Distribuir la Contribución bajo la **GNU General Public License v3.0 o posterior (GPL-3.0-or-later)** o cualquier otra licencia de código abierto aprobada por la OSI que el Comité Técnico determine.
3. Sublicenciar y distribuir la Contribución y sus obras derivadas a terceros bajo **términos y licencias comerciales propietarias alternativas**, sin que ello active las cláusulas de copyleft para dichos licenciatarios comerciales.

---

## 4. CONCESIÓN DE LICENCIA DE PATENTES (PATENT GRANT)

El Colaborador otorga por el presente al Proyecto y a los destinatarios del software una **licencia de patente no exclusiva, perpetua, irrevocable, mundial y libre de regalías** para fabricar, haber fabricado, usar, ofrecer en venta, vender, importar y transferir de cualquier otra manera la Contribución, en la medida en que las patentes en cuestión sean de titularidad del Colaborador o licenciatarias y resulten necesariamente infringidas por la propia Contribución.

---

## 5. DECLARACIONES Y GARANTÍAS DEL COLABORADOR

El Colaborador declara y garantiza que:
1. **Originalidad:** Cada Contribución que envía es de su exclusiva autoría original o bien cuenta con la autorización expresa del legítimo titular para otorgar las licencias aquí descritas.
2. **Propiedad Intelectual:** La Contribución no infringe derechos de autor, secretos comerciales, patentes ni acuerdos de confidencialidad de ningún tercero.
3. **Autorización Laboral:** Si la Contribución fue creada en el marco de una relación de empleo o encargo, el Colaborador declara que cuenta con la aprobación de su empleador para enviar el código bajo este CLA, o que su empleador ha firmado un Acuerdo Corporativo de Contribución (Corporate CLA).

---

## 6. ATRIBUCIÓN Y RECONOCIMIENTO MORAL

El Proyecto se compromete a:
- Mantener la atribución del Colaborador en el registro de control de versiones de Git (`Author` y `Committer`).
- Incluir al Colaborador en el archivo público de colaboradores y créditos del proyecto, salvo que el propio colaborador solicite explícitamente el anonimato.

---

## 7. CÓMO FIRMAR O ACEPTAR EL CLA

La aceptación de este acuerdo se realiza de manera transparente y automatizada:

1. **A través de Pull Request (DCO / CLA Bot):**  
   Al enviar un Pull Request en el repositorio de GitHub, el bot oficial de SamuLibre verificará si has aceptado el CLA. Puedes firmarlo electrónicamente comentando en el PR:
   ```text
   I have read the CLA Document and I hereby accept the SamuLibre Contributor License Agreement.
   ```
2. **Mediante Developer Certificate of Origin (DCO):**  
   Firma tus commits en Git utilizando la bandera `-s` o `--signoff`:
   ```bash
   git commit -s -m "feat(scanner): add new detection heuristic rule"
   ```
   La inclusión de la línea `Signed-off-by: Tu Nombre <tu.email@ejemplo.com>` certifica tu conformidad con los términos del presente CLA.

Para consultas sobre acuerdos corporativos de contribución (CCLA): 📧 **`cla@samulibre.org`**.
