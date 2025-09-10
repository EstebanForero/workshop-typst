// Plantilla para Informe Ejecutivo de Vulnerabilidades VM
#set document(
  title: "Informe Técnico: Análisis de Vulnerabilidades",
  author: "Tu Nombre/Empresa",
  date: auto,
)

// ================================================================
// Bloque de Código para Etiquetas de Vulnerabilidad (Método Simple)
// ================================================================

/// Diccionario que define los niveles de severidad de vulnerabilidades.
/// Se especifica tanto el color de fondo como el de texto manualmente.
#let VulnerabilityLevel = (
  critical: (
    label: "Crítica/Critical",
    background: red,
    text_color: white
  ),
  high: (
    label: "Alta/High",
    background: orange,
    text_color: white
  ),
  medium: (
    label: "Media/Medium",
    background: yellow.darken(30%),
    text_color: black // El amarillo oscuro necesita texto negro
  ),
  low: (
    label: "Baja/Low",
    background: blue,
    text_color: white
  ),
  informative: (
    label: "Informativa/Informative",
    background: gray,
    text_color: white
  )
)

/// Crea una etiqueta de color tipo "tag" para un nivel de vulnerabilidad.
/// Esta versión es más simple y lee todo desde el diccionario.
#let vulnerability_label(level) = {
  assert(
    type(level) == dictionary and "label" in level and "background" in level and "text_color" in level,
    message: "Argument must be a member of VulnerabilityLevel.",
  )
  
  box(
    fill: level.background,
    inset: (x: 7pt, y: 3pt),
    radius: 4pt,
    text(
      fill: level.text_color, // Lee el color del texto directamente
      size: 8pt,
      weight: "bold",
      level.label,
    ),
  )
}

// Configuración de página
#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 2cm),
  numbering: "1",
  header: context [
    #if counter(page).get().first() > 1 [
      #line(length: 100%, stroke: 0.5pt + gray)
      #v(0.3em)
      #text(size: 9pt, fill: gray)[Informe Técnico - Análisis de Vulnerabilidades VM]
    ]
  ],
  footer: context [
    #line(length: 100%, stroke: 0.5pt + gray)
    #v(0.2em)
    #grid(
      columns: (1fr, auto, 1fr),
      align: (left, center, right),
      text(size: 9pt, fill: gray)[Confidencial],
      text(size: 9pt)[Página #counter(page).display()],
      text(size: 9pt, fill: gray)[#datetime.today().display()]
    )
  ]
)

// Configuración de texto
#set text(font: "Arial", size: 11pt)
#set par(justify: true, leading: 0.6em)

// Estilos de títulos
#show heading.where(level: 1): it => [
  #pagebreak(weak: true)
  #v(1.5em)
  #text(size: 18pt, weight: "bold", fill: rgb("#1f4788"))[#it.body]
  #v(0.8em)
  #line(length: 100%, stroke: 2pt + rgb("#1f4788"))
  #v(1em)
]

#show heading.where(level: 2): it => [
  #v(1.2em)
  #text(size: 14pt, weight: "bold", fill: rgb("#2c5aa0"))[#it.body]
  #v(0.6em)
]

#show heading.where(level: 3): it => [
  #v(1em)
  #text(size: 12pt, weight: "bold")[#it.body]
  #v(0.4em)
]

// Función para crear cajas de alerta
#let alert_box(title: "", content: "", color: rgb("#ff6b6b")) = [
  #rect(
    width: 100%,
    stroke: 2pt + color,
    radius: 5pt,
    fill: color.lighten(95%),
    inset: 10pt
  )[
    #if title != "" [
      #text(weight: "bold", fill: color)[#title]
      #v(0.3em)
    ]
    #content
  ]
]

// Función para crear cajas de información
#let info_box(content: "") = [
  #rect(
    width: 100%,
    stroke: 1pt + rgb("#4a90e2"),
    radius: 3pt,
    fill: rgb("#4a90e2").lighten(95%),
    inset: 8pt
  )[
    #content
  ]
]

// Función para tabla de vulnerabilidades
#let vuln_table(data) = [
  #table(
    columns: (auto, 1fr, auto, auto),
    stroke: 0.5pt + gray,
    fill: (x, y) => if y == 0 { rgb("#1f4788").lighten(90%) } else if calc.odd(y) { rgb("#f8f9fa") },
    table.header(
      [*ID*], [*Descripción*], [*Severidad*], [*Estado*]
    ),
    ..data
  )
]

// ==================== PORTADA ====================
#align(center)[
  #v(3cm)
  
  #text(size: 24pt, weight: "bold", fill: rgb("#1f4788"))[
    INFORME TÉCNICO
  ]
  
  #v(0.5em)
  #text(size: 16pt)[
    Análisis de Vulnerabilidades en Máquinas Virtuales
  ]
  
  #v(2cm)
  
  #rect(
    width: 80%,
    stroke: 1pt + rgb("#1f4788"),
    radius: 5pt,
    fill: rgb("#1f4788").lighten(95%),
    inset: 15pt
  )[
    #grid(
      columns: (auto, 1fr),
      row-gutter: 0.8em,
      align: (left, left),
      
      [*Cliente:*], [Propietario de las máquinas],
      [*Fecha:*], [#datetime.today().display("[day]/[month]/[year]")],
      [*Preparado por:*], [Santiago Sabogal Millan, Esteban Fernando Forero Montejo, Laura Maria Franco Ulloa],
      [*Clasificación:*], [Confidencial],
      [*Versión:*], [1.0]
    )
  ]
  
  #v(1fr)
  
  #text(size: 9pt, fill: gray)[
    Este documento contiene información confidencial y está destinado únicamente para uso interno de la organización.
  ]
]

// ==================== RESUMEN EJECUTIVO ====================
= Resumen Técnico


== Hallazgos Principales

Durante el período de evaluación comprendido en la fecha de hoy, de las máquinas virtuales Metasplitable y Bee Box, se identificaron *136 vulnerabilidades* distribuidas de la siguiente manera:

- *Críticas:* 16 vulnerabilidades que requieren atención inmediata
- *Altas:* 19 vulnerabilidades que deben ser atendidas en un plazo máximo de 30 días
- *Medias:* 75 vulnerabilidades programadas para resolución en los próximos 90 días
- *Bajas:* 26 vulnerabilidades de seguimiento continuo

#alert_box(
  title: "Riesgo Principal Identificado",
  content: [
    [DESCRIPCIÓN DEL RIESGO MÁS CRÍTICO ENCONTRADO]
    
    *Impacto Estimado:* [DESCRIPCIÓN DEL IMPACTO]
    
    *Recomendación Inmediata:* [ACCIÓN PRIORITARIA]
  ],
  color: rgb("#ff4757")
)

== Recomendaciones Estratégicas

1. *Implementación inmediata* de parches críticos en sistemas identificados
2. *Fortalecimiento* de la configuración de seguridad en máquinas virtuales
3. *Establecimiento* de un programa de monitoreo continuo
4. *Capacitación* del personal técnico en mejores prácticas de seguridad


// ==================== METODOLOGÍA ====================
= Metodología de Evaluación

== Alcance del Análisis

La evaluación se realizó sobre la siguiente infraestructura:

- *Número de máquinas virtuales analizadas:* 2
- *Sistemas operativos evaluados:* Linux (Ubuntu)
- *Hipervisores incluidos:* VMware

== Herramientas Utilizadas

#table(
  columns: (1fr, 2fr, 1fr),
  stroke: 0.5pt + gray,
  fill: (x, y) => if calc.odd(y) { rgb("#f8f9fa") },
  
  [*Herramienta*], [*Propósito*], [*Versión*],
  [Nessus Essentials], [Escaneo de vulnerabilidades], [10.9.3],
  [Nmap], [Descubrimiento de servicios], [7.97],
  [Metasploit], [Validación de vulnerabilidades], [X.X.X],
)

== Criterios de Clasificación

Las vulnerabilidades se clasificaron utilizando el estándar CVSS v3.0:

- *Crítica (9.0-10.0):* Explotación inmediata posible, impacto severo
- *Alta (7.0-8.9):* Explotación probable, impacto significativo
- *Media (4.0-6.9):* Explotación posible con condiciones específicas
- *Baja (0.1-3.9):* Impacto limitado o explotación compleja

// ==================== HALLAZGOS DETALLADOS ====================
= Hallazgos Detallados de Nmap


= Hallazgos Detallados de Nessus Essentials

== Vulnerabilidades Críticas

#alert_box(
  title: "Atención Inmediata Requerida",
  content: [
    Las siguientes vulnerabilidades requieren acción inmediata debido a su alto riesgo de explotación y potencial impacto en la organización.
  ],
  color: rgb("#ff4757")
)

=== Máquina Metasploitable

#vuln_table((
  [VULN-M001], [Canonical Ubuntu Linux SEoL (8.04.x)], [Crítica], [Pendiente],
  [VULN-M002], [UnrealIRCd Backdoor Detection], [Crítica], [Pendiente],
  [VULN-M003], [VNC Server 'password' Password], [Crítica], [Pendiente],
  [VULN-M004], [SSL Version 2 and 3 Protocol Detection], [Crítica], [Pendiente],
  [VULN-M005], [Bind Shell Backdoor Detection], [Crítica], [Pendiente],
  [VULN-M006], [Apache Tomcat SEoL (<= 5.5.x)], [Crítica], [Pendiente],
  [VULN-M007], [Apache Tomcat AJP Connector Request Injection (Ghostcat)], [Crítica], [Pendiente],
  [VULN-M008], [Apache Tomcat Default Files], [Crítica], [Pendiente],
  [VULN-M009], [Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)], [Crítica], [Pendiente],
))

=== Máquina Bee Box

#vuln_table((
  [VULN-B001], [CriticalSamba 'AndX' Request Heap-Based Buffer Overflow], [Crítica], [Pendiente],
  [VULN-M004], [SSL Version 2 and 3 Protocol Detection], [Crítica], [Pendiente],
))

== Vulnerabilidades de Alta Prioridad

=== Máquina Metasploitable

#vuln_table((
  [VULN-M010], [rlogin Service Detection], [Alta], [Pendiente],
  [VULN-M011], [rsh Service Detection], [Alta], [Pendiente],
  [VULN-M012], [Samba Badlock Vulnerability], [Alta], [Pendiente],
  [VULN-M013], [NFS Shares World Readable], [Alta], [Pendiente],
  [VULN-M014], [SSL Medium Strength Cipher Suites Supported (SWEET32)], [Alta], [Pendiente]
))

=== Máquina Bee Box

#vuln_table((
  [VULN-B002], [Drupal Database Abstraction API SQLi], [Alta], [Pendiente],
  [VULN-B003], [Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS], [Alta], [Pendiente],
  [VULN-M014], [SSL Medium Strength Cipher Suites Supported (SWEET32)], [Alta], [Pendiente],
  [VULN-B004], [OpenSSL Heartbeat Information Disclosure (Heartbleed)], [Alta], [Pendiente],
  [VULN-M012], [Samba Badlock Vulnerability], [Alta], [Pendiente],
  [VULN-B005], [SNMP Agent Default Community Name (public)], [Alta], [Pendiente],
))

== Vulnerabilidades de Prioridad Media

=== Máquina Metasploitable

#vuln_table((
  [VULN-M015], [], [Crítica], [Pendiente],
  [VULN-M016], [], [Crítica], [Pendiente],
  [VULN-M017], [], [Crítica], [Pendiente],
  [VULN-M018], [], [Crítica], [Pendiente],
  [VULN-M019], [], [Crítica], [Pendiente]
))

=== Máquina Bee Box

#vuln_table((
  [VULN-B006], [], [Crítica], [Pendiente],
))
#pagebreak()

= Vulnerabilidades Críticas

== VULN-B001
 
=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* está ejecutando *Apache Tomcat 5.5* en *Linux Kernel 2.6 (Ubuntu 8.04)*. Esta versión llegó a su *Fin de Vida Útil (EoL) el 30 de septiembre de 2012*.  
*Riesgo para el Negocio:* Este servicio web no ha recibido parches de seguridad en más de *12 años*, lo que lo deja expuesto a múltiples *vulnerabilidades críticas conocidas y explotables*. Dado que Tomcat suele usarse como contenedor de aplicaciones empresariales, el riesgo de *compromiso de datos* y *ejecución remota de código* es extremadamente alto.  
*Urgencia:* *Se requiere una actualización o desmantelamiento inmediato.* Mantener este servicio en producción representa un *riesgo inaceptable* para la seguridad.  
*Acción:* Migrar las aplicaciones a una versión soportada de *Apache Tomcat (>= 9.0/10.1 LTS)* o considerar plataformas alternativas modernas. Este host debe tratarse como *comprometido de forma crítica*.  
 
=== Análisis Técnico
- *Nombre:* Apache Tomcat SEoL (<= 5.5.x)  
- *ID del Plugin:* 171340  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Remote – Web Application  
- *Publicado:* 30 de septiembre de 2012 (EoL oficial)  
- *Modificado:* 26 de marzo de 2025  
 
*Impacto:*  
- *Versión Detectada:* 5.5  
- *Fecha de Fin de Vida de Seguridad:* 30 de septiembre de 2012  
- *Tiempo desde el EoL:* ~12 años  
- *Host y Puerto Afectado:* 192.168.122.187 en el puerto 8180/tcp (servicio web)  
 
Esto deja al servicio web expuesto a vulnerabilidades ampliamente conocidas en *Tomcat 5.5*, que incluyen *ejecución remota de código, bypass de autenticación, divulgación de información sensible* y *ataques de denegación de servicio*. El riesgo se ve amplificado por la ejecución en un sistema operativo también sin soporte (Ubuntu 8.04).  
 
*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v3.0:* 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  
 
=== Acciones Recomendadas
1. *Contención Inmediata:* Restringir acceso a este puerto y servicio.  
2. *Migración / Actualización:* Mover las aplicaciones a *Tomcat 9.0/10.1 LTS* en un sistema operativo con soporte.  
3. *Fortalecimiento de la Infraestructura:* Implementar *WAF (Web Application Firewall)* y controles de segmentación de red.  
4. *Revisión Forense:* Asumir compromiso, revisar registros y buscar indicadores de intrusión.  
5. *Política de Ciclo de Vida:* Establecer control estricto sobre versiones soportadas de frameworks y servidores de aplicaciones.  
 
*Conclusión:* El servicio *Apache Tomcat 5.5* en *192.168.122.187:8180* está *fuera de soporte desde hace más de 12 años* y expuesto públicamente. Representa un *riesgo crítico* y debe ser migrado o retirado de inmediato.  

== VULN-B002

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* expone múltiples servicios (SMTP, Web y PostgreSQL) que permiten el uso de *protocolos inseguros SSL 2.0 y SSL 3.0*. Estos protocolos son considerados *obsoletos y criptográficamente débiles*, vulnerables a ataques como *POODLE* y *downgrade attacks*.  
*Riesgo para el Negocio:* La presencia de SSLv2/SSLv3 expone la confidencialidad e integridad de las comunicaciones cifradas, permitiendo a atacantes realizar *ataques de intermediario (MITM)* y descifrar sesiones. Además, el incumplimiento de estándares como *PCI DSS v3.1* implica un riesgo de *no conformidad regulatoria*.  
*Urgencia:* *La desactivación inmediata es obligatoria.* Mantener SSLv2/SSLv3 habilitado expone servicios críticos de correo, web y base de datos a ataques triviales.  
*Acción:* Reconfigurar los servicios afectados para *deshabilitar SSLv2/SSLv3* y forzar el uso de *TLS 1.2 o superior* con *cifrados fuertes*.  

=== Análisis Técnico
- *Nombre:* SSL Version 2 and 3 Protocol Detection  
- *ID del Plugin:* 20007  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Remote – Encryption / Protocol Weakness  
- *Publicado:* 2014 (desuso oficial de SSL 3.0 por NIST)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *Protocolos inseguros detectados:* SSLv2, SSLv3  
- *Cifrados inseguros identificados:* RC4, DES, 3DES, RC2, export-grade (≤ 40 bits)  
- *Servicios y Puertos Afectados:*  
  - 192.168.122.187:25/tcp (SMTP)  
  - 192.168.122.187:443/tcp (HTTPS)  
  - 192.168.122.187:5432/tcp (PostgreSQL)  
  - 192.168.122.187:8443/tcp (HTTPS-alt)  
  - 192.168.122.187:9443/tcp (HTTPS-alt)  

La coexistencia de múltiples servicios con SSLv2/SSLv3 activos amplifica la superficie de ataque. Los atacantes pueden explotar debilidades en *negociación de sesión, padding CBC, y suites de cifrado débiles* para descifrar tráfico o inyectar comandos.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v3.0:* 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Bloquear conexiones externas inseguras y restringir accesos de prueba.  
2. *Reconfiguración de Servicios:*  
   - Deshabilitar *SSLv2/SSLv3* en SMTP, Apache/Tomcat y PostgreSQL.  
   - Forzar *TLS 1.2 o superior* (idealmente TLS 1.3).  
   - Usar *cifrados modernos*: AES-GCM, ChaCha20-Poly1305.  
3. *Compatibilidad Controlada:* Solo habilitar compatibilidad con TLS 1.2 en caso de clientes heredados.  
4. *Verificación:* Ejecutar escaneos posteriores con *nmap --script ssl-enum-ciphers* o Nessus para confirmar desactivación.  
5. *Política de Seguridad:* Incluir la gestión de protocolos y cifrados en la política de hardening corporativa.  

*Conclusión:* El host *192.168.122.187* presenta *protocolos criptográficos obsoletos (SSLv2/SSLv3)* expuestos en *múltiples servicios críticos*. Esto representa un *riesgo severo de confidencialidad e integridad* y un *incumplimiento normativo*. La corrección debe aplicarse de inmediato.  

== VULN-B003

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Ubuntu Linux 8.04 (Hardy Heron)*, cuyo soporte de seguridad finalizó el *9 de mayo de 2013*.  
*Riesgo para el Negocio:* Este sistema no ha recibido parches en más de *12 años*, quedando expuesto a *todas las vulnerabilidades descubiertas desde su EoL*. Ejecutar un sistema operativo sin soporte constituye un *riesgo crítico de seguridad y cumplimiento normativo*, especialmente si alberga servicios expuestos (web, bases de datos, correo).  
*Urgencia:* *Se requiere migración o retiro inmediato.* Un sistema sin soporte no puede ser asegurado, y los atacantes pueden explotar vulnerabilidades conocidas de manera trivial.  
*Acción:* Migrar los servicios a una versión con soporte (*Ubuntu 22.04 LTS / 24.04 LTS*) o a otra distribución soportada. El host debe tratarse como *altamente vulnerable y posiblemente comprometido*.  

=== Análisis Técnico
- *Nombre:* Canonical Ubuntu Linux SEoL (8.04.x)  
- *ID del Plugin:* 201352  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Combinado – Riesgo General (SO sin soporte)  
- *Publicado:* 9 de mayo de 2013 (EoL oficial)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *SO Detectado:* Ubuntu Linux 8.04 (Hardy Heron)  
- *Fecha de Fin de Vida de Seguridad:* 9 de mayo de 2013  
- *Tiempo desde el EoL:* ~12 años  
- *Host y Puerto Afectado:* 192.168.122.187 en el puerto 80/tcp (servicio web)  

El sistema operativo carece de *mecanismos de actualización y soporte oficial*. Esto lo deja vulnerable a ataques conocidos como *Heartbleed, Shellshock, Dirty COW, EternalBlue*, entre muchos otros que surgieron en la última década. Su uso compromete la *seguridad, disponibilidad y confiabilidad* de los servicios desplegados.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v3.0:* 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Limitar acceso externo al host y monitorear en busca de explotación activa.  
2. *Migración / Actualización:* Migrar servicios a *Ubuntu 22.04/24.04 LTS* o sistemas equivalentes soportados.  
3. *Fortalecimiento:* Migrar aplicaciones a plataformas seguras con parches activos.  
4. *Revisión Forense:* Tratar el sistema como potencialmente comprometido, revisar registros e integridad.  
5. *Política de Ciclo de Vida:* Implementar procesos de gestión de versiones y reemplazo oportuno de sistemas obsoletos.  

*Conclusión:* El host *192.168.122.187* opera con un *sistema operativo sin soporte desde hace más de 12 años* y expone servicios en red. Constituye un *riesgo crítico e inaceptable* y debe ser *retirado o migrado de inmediato*.  

== VULN-B004

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* utiliza *claves SSH generadas con una librería OpenSSL defectuosa en Debian/Ubuntu* (CVE-2008-0166). Este bug en el generador de números aleatorios reduce drásticamente la entropía, haciendo que las claves sean *predecibles*.  
*Riesgo para el Negocio:* Un atacante puede recuperar fácilmente las claves privadas asociadas, permitiendo *interceptar sesiones SSH, realizar ataques de hombre en el medio (MITM)* o incluso *suplantar al servidor*. Cualquier comunicación cifrada con este host debe considerarse comprometida.  
*Urgencia:* *Reemplazo inmediato de todas las claves criptográficas*. El sistema debe tratarse como comprometido hasta regenerar el material criptográfico.  
*Acción:* Regenerar todas las claves SSH, SSL y OpenVPN en un sistema actualizado con librerías OpenSSL corregidas. Revocar las claves antiguas y desplegar nuevas con suficiente entropía.  

=== Análisis Técnico
- *Nombre:* Debian OpenSSH/OpenSSL Package Random Number Generator Weakness  
- *ID del Plugin:* 32314  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Criptografía / SSH Weak Keys  
- *Publicado:* Mayo 2008  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-2008-0166  
- *Debilidad:* Claves criptográficas generadas con bajo nivel de entropía → *fácilmente adivinables*.  
- *Servicios Afectados:* SSH (22/tcp), y cualquier otro servicio que use claves generadas en el host (SSL/TLS, OpenVPN).  
- *Vector de Ataque:* Acceso remoto vía red. Un atacante con la lista precomputada de claves débiles puede comprometer la autenticidad y confidencialidad de sesiones en segundos.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  
- *Puntuación Base CVSS v3.0:* N/A (previo a la estandarización, pero se considera *10.0 crítico*).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Bloquear temporalmente accesos SSH externos hasta reemplazar las claves.  
2. *Regeneración de Material Criptográfico:*  
   - Regenerar claves SSH en sistemas con OpenSSL corregido.  
   - Regenerar certificados SSL y claves OpenVPN si fueron creados en el mismo sistema.  
3. *Revocación:* Invalidar todas las claves comprometidas y distribuir nuevas de manera segura.  
4. *Monitoreo:* Revisar accesos sospechosos que indiquen uso indebido de las claves comprometidas.  
5. *Política de Seguridad:* Asegurar que la generación de claves use fuentes robustas de entropía y auditar librerías criptográficas.  

*Conclusión:* El host *192.168.122.187* utiliza *claves SSH débiles generadas con un OpenSSL defectuoso (CVE-2008-0166)*, lo que permite comprometer la autenticidad y confidencialidad de las comunicaciones. Se requiere una *regeneración urgente de todas las claves criptográficas*.  

== VULN-B005

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* presenta *certificados SSL generados con una librería OpenSSL defectuosa en Debian/Ubuntu* (CVE-2008-0166). Este error en el generador de números aleatorios hace que las claves privadas sean *predecibles* y, por lo tanto, incapaces de garantizar la seguridad de las comunicaciones.  
*Riesgo para el Negocio:* Un atacante puede recuperar la clave privada asociada al certificado SSL, lo que permite *descifrar sesiones cifradas, ejecutar ataques de hombre en el medio (MITM)* o suplantar servicios críticos como *SMTP* y *PostgreSQL*. Esto compromete la *confidencialidad* y la *integridad* de la información transmitida.  
*Urgencia:* *Se requiere regeneración inmediata de todos los certificados y claves asociadas*. El material criptográfico actual debe considerarse comprometido.  
*Acción:* Revocar y regenerar todos los certificados SSL afectados en un sistema actualizado con OpenSSL corregido, y redistribuir las claves de manera segura.  

=== Análisis Técnico
- *Nombre:* Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)  
- *ID del Plugin:* 32321  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Criptografía / SSL Weak Keys  
- *Publicado:* Mayo 2008  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-2008-0166  
- *Debilidad:* Certificados SSL generados con bajo nivel de entropía → *claves adivinables*.  
- *Servicios y Puertos Afectados:*  
  - 192.168.122.187:25/tcp (SMTP con SSL débil)  
  - 192.168.122.187:5432/tcp (PostgreSQL con SSL débil)  
- *Vector de Ataque:* Acceso remoto vía red. Un atacante con listas precomputadas de claves débiles puede *descifrar tráfico cifrado o suplantar el servidor*.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  
- *Puntuación Base CVSS v3.0:* N/A (anterior a su estandarización, pero se clasifica como *crítico*).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Restringir accesos a servicios que utilicen SSL débil hasta reemplazar los certificados.  
2. *Regeneración de Certificados:*  
   - Emitir nuevos certificados SSL en un sistema actualizado con OpenSSL corregido.  
   - Reemplazar certificados en *SMTP y PostgreSQL* y en cualquier otro servicio afectado.  
3. *Revocación:* Invalidar certificados antiguos para evitar su uso indebido.  
4. *Monitoreo:* Revisar registros de acceso y conexiones sospechosas que indiquen ataques MITM o descifrado.  
5. *Política de Seguridad:* Asegurar que todos los sistemas cuenten con librerías criptográficas actualizadas y que las claves/certificados se roten periódicamente.  

*Conclusión:* El host *192.168.122.187* usa *certificados SSL débiles generados con OpenSSL defectuoso (CVE-2008-0166)*, lo que permite comprometer la seguridad de servicios críticos. Se requiere *regeneración inmediata de todo el material criptográfico SSL*.  

== VULN-B006

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta una versión de *UnrealIRCd* comprometida con un *backdoor crítico (CVE-2010-2075)*, que permite a un atacante remoto ejecutar *código arbitrario como root*.  
*Riesgo para el Negocio:* Esta vulnerabilidad implica un *compromiso total del sistema*. Un atacante con acceso puede *tomar control completo del servidor, exfiltrar datos, pivotar a otros sistemas internos* y usar la máquina como *punto de ataque*.  
*Urgencia:* *Corrección inmediata obligatoria.* El software actual debe considerarse comprometido, y el host tratado como *comprometido en su totalidad*.  
*Acción:* Reinstalar UnrealIRCd desde fuentes confiables, verificando la integridad mediante *checksums oficiales (MD5/SHA1)*, o eliminar el servicio si no es necesario.  

=== Análisis Técnico
- *Nombre:* UnrealIRCd Backdoor Detection  
- *ID del Plugin:* 46882  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Backdoor / Remote Code Execution (RCE)  
- *Publicado:* Junio 2010  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-2010-2075  
- *Vector de Ataque:* Remoto vía IRC (6667/tcp)  
- *Privilegios de Ejecución:* root (uid=0, gid=0)  
- *Host y Puerto Afectado:* 192.168.122.187:6667/tcp (IRC)  
- *Estado de Explotabilidad:* Confirmado → explotable con *Metasploit* y *CANVAS*.  

La presencia del backdoor implica que el binario de UnrealIRCd fue manipulado maliciosamente en la distribución oficial (2010). Esto permite que cualquier atacante con conocimiento de la vulnerabilidad ejecute comandos arbitrarios en el sistema afectado.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  
- *Puntuación Base CVSS v3.0:* No disponible, pero el impacto corresponde a *ejecución remota con privilegios de root*.  

=== Acciones Recomendadas
1. *Contención Inmediata:* Aislar el servidor de la red para evitar explotación activa.  
2. *Reinstalación Segura:*  
   - Descargar UnrealIRCd únicamente desde fuentes oficiales verificadas.  
   - Validar integridad con *checksums (MD5/SHA1)* publicados.  
   - Reinstalar o eliminar el servicio IRC si no es requerido.  
3. *Revisión Forense:* Tratar el host como *totalmente comprometido*. Analizar registros, buscar puertas traseras adicionales e indicadores de compromiso.  
4. *Seguridad de Red:* Bloquear tráfico IRC externo en el puerto 6667 si no es estrictamente necesario.  
5. *Política de Software:* Asegurar procesos de validación de binarios en descargas y actualizaciones.  

*Conclusión:* El servicio *UnrealIRCd en 192.168.122.187:6667* contiene un *backdoor crítico* que otorga control total del host a atacantes remotos. Este hallazgo representa un *riesgo máximo* y requiere *reinstalación inmediata y revisión forense completa*.  

== VULN-B007

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* presenta un *backdoor tipo bind shell* en el puerto *1524/tcp*, que permite a cualquier atacante conectarse y ejecutar comandos directamente con privilegios de *root* sin necesidad de autenticación.  
*Riesgo para el Negocio:* Este hallazgo confirma un *compromiso total del sistema*. Un atacante puede usar este acceso para *tomar control completo del servidor, exfiltrar información, pivotar hacia la red interna* y desplegar otras puertas traseras o malware.  
*Urgencia:* *Acción inmediata obligatoria.* El host debe tratarse como comprometido y reinstalarse desde cero tras un análisis forense.  
*Acción:* Desconectar el servidor de la red, realizar una revisión forense y reinstalar el sistema operativo desde medios confiables.  

=== Análisis Técnico
- *Nombre:* Bind Shell Backdoor Detection  
- *ID del Plugin:* 51988  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Backdoor / Remote Code Execution (RCE)  
- *Publicado:* Fecha desconocida (detectado por Nessus en entornos comprometidos)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *Servicio Afectado:* Puerto 1524/tcp (wild shell)  
- *Privilegios de Ejecución:* root (uid=0, gid=0)  
- *Vector de Ataque:* Conexión remota directa sin autenticación  
- *Evidencia:* Nessus ejecutó el comando `id` con éxito, confirmando acceso total al sistema con privilegios root.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v3.0:* 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Aislar el host de la red para evitar accesos externos.  
2. *Revisión Forense:* Analizar registros, procesos y posibles movimientos laterales realizados por atacantes.  
3. *Reinstalación Segura:* Eliminar la instalación actual y reinstalar el sistema operativo desde fuentes confiables.  
4. *Regeneración de Credenciales:* Considerar comprometidas todas las claves y credenciales utilizadas en este host.  
5. *Política de Seguridad:* Implementar controles de detección temprana (IDS/IPS, EDR) para identificar accesos no autorizados en el futuro.  

*Conclusión:* El host *192.168.122.187* contiene un *bind shell backdoor activo en el puerto 1524/tcp*, otorgando acceso remoto total sin autenticación. Este hallazgo confirma que el sistema está *completamente comprometido* y requiere *reinstalación inmediata tras un análisis forense*.  

== VULN-B008

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta un servicio *Samba vulnerable a un desbordamiento de búfer en solicitudes AndX (CVE-2012-0870)*. Este fallo permite a un atacante remoto ejecutar *código arbitrario con los privilegios del servicio Samba*, lo que compromete la confidencialidad, integridad y disponibilidad del sistema.  
*Riesgo para el Negocio:* La explotación exitosa concede control total del servicio compartido y puede servir de vector para el *compromiso completo del host*. Dado que Samba se utiliza en entornos de intercambio de archivos, este fallo puede usarse para *propagación lateral en redes corporativas*.  
*Urgencia:* *Se requiere aplicación inmediata de parches.* El servicio debe considerarse vulnerable a explotación remota.  
*Acción:* Actualizar Samba a una versión corregida y revisar la integridad del sistema.  

=== Análisis Técnico
- *Nombre:* Samba 'AndX' Request Heap-Based Buffer Overflow  
- *ID del Plugin:* 58327  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Ejecución Remota de Código (RCE)  
- *Publicado:* Febrero 2012  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-2012-0870  
- *Vector de Ataque:* Red (SMB/CIFS – puerto 445/tcp)  
- *Privilegios de Ejecución:* Igual a los del servicio Samba (potencial escalamiento posterior).  
- *Host y Puerto Afectado:* 192.168.122.187:445/tcp (CIFS/SMB)  
- *Posible Consecuencia:* Ejecución remota de código o denegación de servicio.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  
- *Puntuación Base CVSS v3.0:* N/A (vulnerabilidad anterior a su estandarización, pero impacto equivalente a *crítico*).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Restringir acceso externo al puerto 445/tcp hasta la aplicación de parches.  
2. *Actualización de Software:* Instalar la versión corregida de Samba disponible en el repositorio oficial.  
3. *Monitoreo y Forense:* Revisar registros de Samba y del sistema en busca de explotación activa o movimientos laterales.  
4. *Segmentación de Red:* Limitar el acceso SMB únicamente a clientes autorizados en redes internas.  
5. *Política de Gestión de Parches:* Implementar un ciclo de actualización proactivo para software crítico de red.  

*Conclusión:* El servicio *Samba en 192.168.122.187:445* es vulnerable a un *heap overflow crítico (CVE-2012-0870)* que permite ejecución remota de código. Este riesgo es *máximo* y debe ser mitigado mediante actualización inmediata y control de acceso.  

== VULN-B009

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta un servicio *VNC* protegido con la contraseña trivial *“password”*. Nessus logró autenticarse exitosamente utilizando esta credencial débil.  
*Riesgo para el Negocio:* Un atacante remoto puede tomar *control total de la sesión VNC*, obteniendo acceso al sistema operativo y sus aplicaciones. Esto permite el robo de información, instalación de malware y uso del host como pivote para comprometer otros sistemas.  
*Urgencia:* *Corrección inmediata obligatoria.* Un servicio crítico expuesto con credenciales débiles supone un riesgo inaceptable.  
*Acción:* Deshabilitar temporalmente el servicio VNC, establecer *contraseñas robustas* y, preferiblemente, implementar autenticación más fuerte o encapsular VNC en un canal seguro (ej. *SSH túnel* o *VPN*).  

=== Análisis Técnico
- *Nombre:* VNC Server 'password' Password  
- *ID del Plugin:* 61708  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.critical)  
- *Tipo:* Autenticación Débil / Control Remoto  
- *Publicado:* Fecha indeterminada (detectado por prueba de credenciales débiles)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *Vector de Ataque:* Remoto vía red (puerto 5900/tcp).  
- *Credenciales:* Contraseña detectada = *password*  
- *Host y Puerto Afectado:* 192.168.122.187:5900/tcp (VNC)  
- *Consecuencia:* Compromiso total de la sesión de escritorio remoto, con posibilidad de escalamiento adicional.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Crítico  
- *Puntuación Base CVSS v2.0:* 10.0 (AV:N/AC:L/Au:N/C:C/I:C/A:C)  
- *Puntuación Base CVSS v3.0:* N/A (no asignada, pero impacto equivalente a crítico).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Deshabilitar acceso remoto a VNC en el puerto 5900 hasta corregir la configuración.  
2. *Fortalecimiento de Credenciales:* Configurar una contraseña fuerte y única para VNC.  
3. *Seguridad Adicional:* Encapsular VNC dentro de túneles SSH o VPN para proteger el tráfico.  
4. *Restricción de Acceso:* Limitar el acceso VNC solo a direcciones IP autorizadas.  
5. *Política de Gestión de Accesos:* Incluir pruebas regulares de credenciales débiles en auditorías de seguridad.  

*Conclusión:* El servicio *VNC en 192.168.122.187:5900* utiliza la contraseña trivial *“password”*, lo que concede acceso remoto inmediato a atacantes. Se requiere *corrección urgente* mediante fortalecimiento de credenciales y medidas de seguridad adicionales.  

= Vulnerabilidades Altas

== VULN-B010

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta el servicio *rlogin* en el puerto *513/tcp*. Este protocolo es inseguro porque transmite credenciales en *texto claro*, lo que permite que un atacante en la red intercepte usuarios y contraseñas. Además, rlogin puede aceptar inicios de sesión sin contraseña mediante configuraciones indebidas en *~/.rhosts* o *rhosts.equiv*.  
*Riesgo para el Negocio:* El uso de *rlogin* facilita ataques de *man-in-the-middle (MITM)*, *robo de credenciales* y *bypass de autenticación*. Su exposición en un host comprometido incrementa el riesgo de movimientos laterales dentro de la red.  
*Urgencia:* *El servicio debe deshabilitarse inmediatamente.* Mantenerlo activo expone las credenciales de los usuarios y debilita la postura de seguridad.  
*Acción:* Deshabilitar rlogin en * /etc/inetd.conf* y reemplazarlo por *SSH* con autenticación segura y cifrado robusto.  

=== Análisis Técnico
- *Nombre:* rlogin Service Detection  
- *ID del Plugin:* 10205  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Servicio Inseguro – Autenticación / Transmisión de Credenciales en Claro  
- *Publicado:* 1999 (CVE-1999-0651)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-1999-0651  
- *Vector de Ataque:* Red → Tráfico en texto claro, susceptible a sniffing y spoofing.  
- *Host y Puerto Afectado:* 192.168.122.187:513/tcp (rlogin)  
- *Consecuencias:*  
  - Interceptación de credenciales en texto claro.  
  - Autenticación débil o inexistente vía *.rhosts*.  
  - Potencial de escalamiento de privilegios y compromiso completo del sistema.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v2.0:* 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P)  
- *Puntuación Base CVSS v3.0:* No disponible (vulnerabilidad histórica, pero se clasifica como *alto*).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Deshabilitar el servicio rlogin en * /etc/inetd.conf* y reiniciar inetd.  
2. *Migración a Protocolos Seguros:* Usar *SSH* en lugar de rlogin para acceso remoto.  
3. *Revisión de Configuración:* Eliminar archivos *.rhosts* y *rhosts.equiv* para evitar accesos indebidos.  
4. *Segmentación de Red:* Limitar acceso remoto a servicios estrictamente necesarios.  
5. *Política de Seguridad:* Prohibir explícitamente el uso de protocolos heredados e inseguros en la infraestructura.  

*Conclusión:* El servicio *rlogin en 192.168.122.187:513* es inseguro y expone credenciales en claro, lo que representa un *alto riesgo de compromiso*. Debe ser *deshabilitado inmediatamente* y sustituido por *SSH* con autenticación fuerte.  

== VULN-B011

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta el servicio *rsh* en el puerto *514/tcp*. Este protocolo transmite credenciales en *texto claro* y permite, bajo ciertas configuraciones, *accesos sin contraseña* utilizando archivos *.rhosts* o *rhosts.equiv*.  
*Riesgo para el Negocio:* El uso de *rsh* expone credenciales a ataques de *man-in-the-middle (MITM)* y puede facilitar *movimientos laterales* en la red interna. Además, en entornos comprometidos, este servicio es frecuentemente explotado para escalamiento de privilegios.  
*Urgencia:* *Debe deshabilitarse inmediatamente.* Su uso representa un riesgo de seguridad alto e inaceptable.  
*Acción:* Comentar la línea correspondiente a *rsh* en * /etc/inetd.conf* y reiniciar el proceso *inetd*. Migrar a *SSH* con cifrado fuerte y autenticación robusta.  

=== Análisis Técnico
- *Nombre:* rsh Service Detection  
- *ID del Plugin:* 10245  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Servicio Inseguro – Autenticación / Transmisión en Claro  
- *Publicado:* 1999 (CVE-1999-0651)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-1999-0651  
- *Vector de Ataque:* Tráfico en texto claro → susceptible a sniffing, spoofing y secuestro de sesión.  
- *Host y Puerto Afectado:* 192.168.122.187:514/tcp (rsh)  
- *Consecuencias:*  
  - Interceptación de credenciales.  
  - Autenticación débil o inexistente vía *.rhosts*.  
  - Conversión de accesos de escritura en logins completos.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v2.0:* 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P)  
- *Puntuación Base CVSS v3.0:* No disponible (clasificación previa, pero riesgo equivalente a *alto*).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Deshabilitar el servicio rsh en * /etc/inetd.conf* y reiniciar inetd.  
2. *Migración a Protocolos Seguros:* Sustituir rsh por *SSH*.  
3. *Revisión de Configuración:* Eliminar archivos *.rhosts* y *rhosts.equiv*.  
4. *Restricción de Acceso:* Limitar servicios remotos solo a protocolos cifrados y usuarios autorizados.  
5. *Política de Seguridad:* Bloquear explícitamente protocolos obsoletos como rsh en la infraestructura.  

*Conclusión:* El servicio *rsh en 192.168.122.187:514* transmite credenciales en claro y permite accesos inseguros, representando un *alto riesgo de compromiso*. Debe ser *deshabilitado inmediatamente* y reemplazado por *SSH*.  

== VULN-B012

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Apache Tomcat* con un conector AJP vulnerable (*Ghostcat – CVE-2020-1938, CVE-2020-1745*), escuchando en el puerto *8009/tcp*. La vulnerabilidad permite a un atacante remoto y no autenticado *leer archivos de la aplicación web* y, en escenarios donde se permiten cargas de archivos, lograr *ejecución remota de código (RCE)*.  
*Riesgo para el Negocio:* La explotación exitosa de *Ghostcat* puede otorgar acceso a *archivos sensibles de configuración (ej. WEB-INF/web.xml)* y permitir la inserción de código malicioso, resultando en el *compromiso completo de la aplicación y del servidor*. Dada su amplia explotación en entornos productivos, representa un riesgo *muy alto* de compromiso real.  
*Urgencia:* *Se requiere mitigación inmediata.* La vulnerabilidad es de fácil explotación y se encuentra en la lista de *CISA Known Exploited Vulnerabilities*.  
*Acción:* Actualizar Tomcat a versiones seguras (≥ 7.0.100, 8.5.51, 9.0.31 o posteriores) y restringir el acceso al conector AJP solo a hosts confiables.  

=== Análisis Técnico
- *Nombre:* Apache Tomcat AJP Connector Request Injection (Ghostcat)  
- *ID del Plugin:* 134862  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Lectura de Archivos / Inclusión de Archivos / Ejecución Remota de Código  
- *Publicado:* Febrero 2020  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociados:* CVE-2020-1938, CVE-2020-1745  
- *Vector de Ataque:* Red – conexión al conector AJP (puerto 8009/tcp)  
- *Host y Puerto Afectado:* 192.168.122.187:8009/tcp (ajp13)  
- *Explotabilidad:* Confirmada – se demostró lectura de *WEB-INF/web.xml*.  
- *Consecuencias:* Acceso a archivos internos, fuga de información sensible, potencial ejecución remota de código.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v3.0:* 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
- *Puntuación Base CVSS v2.0:* 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Restringir el acceso al puerto 8009/tcp únicamente a sistemas autorizados o deshabilitar el conector si no es necesario.  
2. *Actualización de Software:* Migrar Tomcat a versiones corregidas (≥ 7.0.100, 8.5.51, 9.0.31 o superiores).  
3. *Endurecimiento de Configuración:* Configurar el AJP connector con autenticación y secretos compartidos.  
4. *Monitoreo:* Revisar logs de Tomcat en busca de intentos de explotación.  
5. *Política de Seguridad:* Asegurar que conectores y servicios no utilizados se encuentren deshabilitados por defecto.  

*Conclusión:* El servicio *Apache Tomcat AJP en 192.168.122.187:8009* es vulnerable a *Ghostcat*, una vulnerabilidad ampliamente explotada que permite *lectura de archivos internos y ejecución remota de código*. Requiere *actualización inmediata* y controles de acceso estrictos.  

== VULN-B013

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta un agente *SNMP* en el puerto *161/udp* con la *community string por defecto “public”*. Esto permite a un atacante no autenticado obtener información sensible sobre el sistema y, dependiendo de la configuración, incluso modificar parámetros críticos.  
*Riesgo para el Negocio:* La exposición de SNMP con credenciales por defecto facilita el *reconocimiento y enumeración de la infraestructura interna*, permitiendo a un atacante recopilar datos sobre interfaces de red, procesos, usuarios y configuración. Esto puede usarse para *movimientos laterales y ataques dirigidos*.  
*Urgencia:* *Corrección inmediata necesaria.* El uso de cadenas por defecto en SNMP es un error crítico de configuración.  
*Acción:* Cambiar la cadena “public” por una *community string fuerte y personalizada* o, preferiblemente, *deshabilitar SNMP* si no es requerido.  

=== Análisis Técnico
- *Nombre:* SNMP Agent Default Community Name (public)  
- *ID del Plugin:* 41028  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Exposición de Información / Configuración Débil  
- *Publicado:* 1999 (CVE-1999-0517)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-1999-0517  
- *Vector de Ataque:* Red (UDP/161 – no autenticado).  
- *Host y Puerto Afectado:* 192.168.122.187:161/udp (SNMP).  
- *Consecuencias:*  
  - Exposición de información sensible del host (interfaz de red, usuarios, procesos).  
  - Posible modificación de configuración si la cadena tiene permisos de escritura.  
  - Aumento de superficie de ataque para comprometer la red.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v2.0:* 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P)  
- *Puntuación Base CVSS v3.0:* No disponible (vulnerabilidad histórica, pero clasificada como *alto*).  

=== Acciones Recomendadas
1. *Contención Inmediata:* Bloquear acceso externo al puerto 161/udp desde redes no autorizadas.  
2. *Fortalecimiento de Configuración:*  
   - Reemplazar la cadena por defecto *public* con una *community string robusta y única*.  
   - Implementar SNMPv3 con autenticación y cifrado si se requiere el servicio.  
3. *Reducción de Superficie de Ataque:* Deshabilitar el servicio SNMP si no es necesario para la operación.  
4. *Segmentación:* Limitar el acceso SNMP únicamente a equipos de gestión autorizados.  
5. *Política de Seguridad:* Prohibir el uso de cadenas por defecto en cualquier servicio expuesto.  

*Conclusión:* El servicio *SNMP en 192.168.122.187:161* utiliza la cadena por defecto *“public”*, lo que permite a atacantes recopilar información sensible y potencialmente alterar configuraciones. Este riesgo es *alto* y requiere *corrección inmediata*.  

== VULN-B014

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta una instalación vulnerable de *Drupal* afectada por la vulnerabilidad crítica *SQL Injection en la API de abstracción de base de datos (CVE-2014-3704, conocido como “Drupalgeddon”)*. Este fallo permite a atacantes remotos no autenticados enviar *peticiones especialmente diseñadas* que resultan en *ejecución arbitraria de SQL*, escalamiento de privilegios y, en muchos casos, *ejecución remota de código*.  
*Riesgo para el Negocio:* La explotación de *Drupalgeddon* es trivial y está ampliamente automatizada en frameworks como *Metasploit*. Un atacante puede comprometer completamente la aplicación web, acceder a datos sensibles, crear cuentas administrativas y ejecutar código PHP arbitrario en el servidor.  
*Urgencia:* *Remediación inmediata obligatoria.* Este fallo ha sido utilizado en campañas masivas de explotación desde 2014.  
*Acción:* Actualizar Drupal a la versión *7.32 o superior* y aplicar controles de seguridad adicionales en la aplicación y el servidor.  

=== Análisis Técnico
- *Nombre:* Drupal Database Abstraction API SQLi (Drupalgeddon)  
- *ID del Plugin:* 78515  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* SQL Injection → Ejecución Remota de Código  
- *Publicado:* Octubre 2014 (SA-CORE-2014-005)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CVE-2014-3704  
- *Explotabilidad:* Confirmada con *Metasploit, Core Impact, CANVAS*.  
- *Vectores de Ataque:* Peticiones web manipuladas a endpoints de Drupal.  
- *Hosts y Puertos Afectados:*  
  - 192.168.122.187:80/tcp (HTTP)  
  - 192.168.122.187:443/tcp (HTTPS)  
  - 192.168.122.187:9080/tcp (HTTP alternativo)  
  - 192.168.122.187:9443/tcp (HTTPS alternativo)  

*Consecuencias:*  
- Ejecución arbitraria de consultas SQL.  
- Robo o manipulación de datos sensibles.  
- Creación de cuentas administrativas falsas.  
- Ejecución remota de PHP y compromiso completo del servidor.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v2.0:* 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P)  
- *Puntuación Base CVSS v3.0:* No asignada, pero considerada equivalente a *crítico (9.8)* en clasificaciones actuales.  

=== Acciones Recomendadas
1. *Contención Inmediata:* Restringir acceso público a los servicios Drupal afectados hasta aplicar parches.  
2. *Actualización de Software:* Migrar a Drupal 7.32 o versiones posteriores soportadas.  
3. *Monitoreo de Integridad:* Revisar la base de datos y los archivos PHP por indicios de explotación activa.  
4. *Refuerzo de Seguridad:* Aplicar reglas WAF que mitiguen SQLi y restringir acceso administrativo solo a IPs autorizadas.  
5. *Política de Ciclo de Vida:* Asegurar actualizaciones continuas en CMS y frameworks web.  

*Conclusión:* El host *192.168.122.187* ejecuta múltiples instancias de *Drupal vulnerable a Drupalgeddon (CVE-2014-3704)* en distintos puertos. Este hallazgo representa un riesgo *muy alto de explotación activa* y debe ser corregido de forma inmediata mediante actualización y fortalecimiento del entorno web.  

= Vulnerabilidades Medias

== VULN-B015

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* soporta *TLS 1.0* en múltiples servicios (SMTP, PostgreSQL, y servicios web en distintos puertos). *TLS 1.0* es un protocolo obsoleto con *fallos criptográficos de diseño conocidos*. Desde *2018*, PCI DSS v3.2 exige su deshabilitación, y desde *2020* la mayoría de navegadores y proveedores dejaron de soportarlo.  
*Riesgo para el Negocio:* El uso de *TLS 1.0* expone las comunicaciones a ataques de *downgrade* y a la explotación de vulnerabilidades criptográficas. Esto reduce la *confianza, cumplimiento normativo* y la protección de datos sensibles en tránsito.  
*Urgencia:* *Debe deshabilitarse TLS 1.0 y migrar a TLS 1.2/1.3 de forma inmediata.*  
*Acción:* Configurar los servicios afectados para usar únicamente *TLS 1.2 o superior* y deshabilitar completamente *TLS 1.0*.  

=== Análisis Técnico
- *Nombre:* TLS Version 1.0 Protocol Detection  
- *ID del Plugin:* 104743  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Protocolos Criptográficos Obsoletos  
- *Publicado:* Marzo 2020 (IETF Draft deprecando SSL/TLS antiguos)  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *CVE Asociado:* CWE-327 (uso de criptografía débil)  
- *Servicios Afectados:*  
  - 192.168.122.187:25/tcp (SMTP)  
  - 192.168.122.187:443/tcp (HTTPS)  
  - 192.168.122.187:5432/tcp (PostgreSQL)  
  - 192.168.122.187:8443/tcp (HTTPS alternativo)  
  - 192.168.122.187:9443/tcp (HTTPS alternativo)  
- *Consecuencias:*  
  - Riesgo de ataques de *downgrade*.  
  - Exposición a vulnerabilidades criptográficas conocidas en TLS 1.0.  
  - No cumplimiento con PCI DSS y estándares de seguridad modernos.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v2.0:* 6.1 (AV:N/AC:H/Au:N/C:C/I:P/A:N)  
- *Puntuación Base CVSS v3.0:* 6.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Deshabilitar TLS 1.0 en todos los servicios afectados.  
2. *Actualización de Protocolos:* Configurar servidores para soportar únicamente *TLS 1.2 o 1.3*.  
3. *Verificación de Compatibilidad:* Asegurar que los clientes soporten TLS modernos antes de la migración.  
4. *Cumplimiento Normativo:* Validar que la infraestructura cumpla PCI DSS, ISO 27001 y mejores prácticas de la industria.  
5. *Monitoreo:* Implementar escaneos periódicos para validar que protocolos obsoletos permanezcan deshabilitados.  

*Conclusión:* El host *192.168.122.187* permite conexiones con *TLS 1.0* en varios servicios críticos, lo cual constituye una debilidad criptográfica y de cumplimiento normativo. Debe ser corregido de inmediato migrando a *TLS 1.2/1.3*.  

== VULN-B016

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* expone el recurso *Apache mod_status* en las rutas * /server-status* a través de HTTP y HTTPS. Esta página muestra información sensible sobre el estado y rendimiento del servidor web, incluyendo *solicitudes activas, direcciones IP de clientes, número de procesos y utilización de CPU*.  
*Riesgo para el Negocio:* La exposición de *mod_status* a atacantes no autenticados permite la *enumeración de usuarios y servicios activos*, facilita la *planificación de ataques DoS* y ayuda a *identificar rutas y patrones de tráfico* para explotación dirigida. Aunque no otorga acceso directo al sistema, amplifica el riesgo de otros ataques.  
*Urgencia:* *Debe restringirse inmediatamente el acceso a /server-status*.  
*Acción:* Configurar Apache para deshabilitar *mod_status* o limitar el acceso únicamente a hosts de administración confiables.  

=== Análisis Técnico
- *Nombre:* Apache mod_status /server-status Information Disclosure  
- *ID del Plugin:* 10677  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Exposición de Información  
- *Publicado:* Históricamente documentado en OWASP y guías de Apache  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *URL Expuestas:*  
  - http://192.168.122.187/server-status  
  - https://192.168.122.187/server-status  
- *Datos Divulgados:*  
  - Peticiones HTTP activas y clientes conectados.  
  - Número de procesos y workers activos/idle.  
  - Estadísticas de uso de CPU y carga de servidor.  
- *Consecuencias:*  
  - Permite reconocimiento de infraestructura y tráfico.  
  - Ayuda en la identificación de usuarios y sesiones activas.  
  - Facilita ataques de fuerza bruta o denegación de servicio dirigidos.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Bloquear acceso público a * /server-status*.  
2. *Configuración de Apache:*  
   - Deshabilitar *mod_status* si no es requerido.  
   - Alternativamente, restringir el acceso mediante directivas *Require host* o *Require ip*.  
3. *Monitoreo:* Revisar logs de acceso a * /server-status* para detectar intentos de reconocimiento.  
4. *Endurecimiento del Servidor Web:* Aplicar mejores prácticas de OWASP y la guía oficial de Apache.  
5. *Política de Seguridad:* Definir que recursos de diagnóstico solo sean accesibles internamente.  

*Conclusión:* La exposición del recurso * /server-status* en *192.168.122.187* divulga información sensible sobre el servidor web Apache. Aunque el riesgo es clasificado como *medio*, puede ser aprovechado para facilitar ataques más graves y debe ser corregido *de inmediato*.  

== VULN-B017

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* permite el uso de los métodos HTTP *TRACE* y *TRACK* en los servicios web (HTTP y HTTPS). Estos métodos, diseñados para depuración, pueden ser aprovechados por atacantes para llevar a cabo ataques como *Cross-Site Tracing (XST)*, que permiten el robo de *cookies de sesión* y otros encabezados sensibles.  
*Riesgo para el Negocio:* La habilitación de métodos de depuración en producción expone información sensible y aumenta la superficie de ataque, comprometiendo la *confidencialidad de datos de autenticación* y debilitando la seguridad de aplicaciones web críticas.  
*Urgencia:* *Debe deshabilitarse inmediatamente el soporte de TRACE/TRACK*.  
*Acción:* Configurar el servidor Apache para bloquear estos métodos mediante la directiva *TraceEnable off* o reglas de reescritura en * /etc/apache2/apache2.conf* o en los *VirtualHosts*.  

=== Análisis Técnico
- *Nombre:* HTTP TRACE / TRACK Methods Allowed  
- *ID del Plugin:* 11213  
- *Severidad:*  #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Exposición de Métodos HTTP Inseguros  
- *Publicado:* Originalmente documentado en CVE-2003-1567, CVE-2004-2320, CVE-2010-0386  
- *Modificado:* 26 de marzo de 2025  

*Impacto:*  
- *Servicios Afectados:*  
  - http://192.168.122.187 (puerto 80/tcp)  
  - https://192.168.122.187 (puerto 443/tcp)  
- *Consecuencias:*  
  - Posible robo de cookies de sesión y cabeceras de autenticación.  
  - Facilita ataques de tipo *Cross-Site Tracing (XST)*.  
  - Exposición innecesaria de funciones de depuración en producción.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  

=== Acciones Recomendadas
1. *Contención Inmediata:* Bloquear TRACE y TRACK mediante reglas de reescritura en la configuración de Apache.  
2. *Configuración de Apache:*  
   - Agregar *TraceEnable off* en la configuración global.  
   - Alternativamente, aplicar reglas *RewriteCond* y *RewriteRule* en cada *VirtualHost*.  
3. *Endurecimiento del Servidor:* Revisar y limitar métodos HTTP permitidos únicamente a los necesarios (GET, POST, PUT, DELETE).  
4. *Pruebas de Validación:* Realizar un nuevo escaneo para confirmar la deshabilitación de métodos inseguros.  
5. *Buenas Prácticas:* Seguir guías OWASP y CIS Benchmarks para servidores web.  

*Conclusión:* El host *192.168.122.187* expone los métodos *TRACE* y *TRACK* en servicios web críticos (HTTP y HTTPS). Aunque se clasifica como *riesgo medio*, esta configuración debilita la seguridad de la aplicación y puede servir como vector de ataques avanzados. Su deshabilitación es obligatoria en entornos de producción.  

== VULN-B018

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Apache Tomcat* en el puerto *8180/tcp*, y contiene *archivos por defecto* (páginas de ejemplo, JSPs y servlets de demostración).  
*Riesgo para el Negocio:* Estos archivos de ejemplo pueden *revelar información sensible* sobre la instalación de Tomcat o el propio host. Tal exposición puede facilitar ataques de reconocimiento, explotación de vulnerabilidades conocidas o uso indebido de componentes de ejemplo.  
*Urgencia:* *Atención prioritaria pero no crítica.* Aunque no representa una explotación directa de alto impacto, se trata de una *mala práctica de configuración* que debe corregirse de inmediato.  
*Acción:* Eliminar páginas y archivos por defecto, reemplazar las páginas de error con versiones personalizadas, y seguir las guías de *Apache Tomcat* u *OWASP* para asegurar la instalación.  

=== Análisis Técnico
- *Nombre:* Apache Tomcat Default Files  
- *ID del Plugin:* 12085  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Insegura (Archivos por Defecto)  
- *Publicado:*  —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187 en 8180/tcp (servicio web Tomcat)  
- *Archivos detectados:*  
  - http://192.168.122.29:8180/tomcat-docs/index.html  
- *Comportamiento adicional:* El servidor no retorna páginas de error personalizadas → posible *divulgación de información del servidor*.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  

=== Acciones Recomendadas
1. *Eliminar Archivos por Defecto:* Borrar páginas de ejemplo, JSPs y servlets instalados por defecto.  
2. *Configurar Páginas de Error Personalizadas:* Prevenir fugas de información a través de páginas de error estándar.  
3. *Seguir Buenas Prácticas:* Aplicar las recomendaciones de *OWASP* y de la documentación oficial de Tomcat para asegurar el despliegue.  
4. *Revisión de Configuración:* Asegurar que no se expongan directorios o documentación sensible en entornos de producción.  

*Conclusión:* La exposición de *archivos por defecto en Tomcat* representa un *riesgo de reconocimiento y fuga de información*. Aunque no es crítico, se debe corregir para prevenir escenarios de ataque más avanzados y mejorar la *higiene de seguridad del servidor*.  

== VULN-B019

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *nginx 1.4.0* en los puertos *8080/tcp* y *8443/tcp*. Esta versión es anterior a *1.17.7* y presenta una vulnerabilidad de *divulgación de información* (CVE-2019-20372).  
*Riesgo para el Negocio:* La divulgación de información puede exponer *detalles sensibles de la infraestructura* (versiones, encabezados y comportamiento del servidor) que pueden ser utilizados por atacantes para planear intrusiones más sofisticadas.  
*Urgencia:* *Actualización recomendada en el corto plazo.* Aunque no se trata de una vulnerabilidad crítica, el uso de versiones obsoletas de nginx aumenta el *riesgo de reconocimiento y explotación futura*.  
*Acción:* Actualizar nginx a la versión *1.17.7 o posterior* en todos los servicios expuestos, especialmente en *puertos accesibles externamente*.  

=== Análisis Técnico
- *Nombre:* nginx < 1.17.7 Information Disclosure  
- *ID del Plugin:* 134220  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Vulnerabilidad de Divulgación de Información  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puertos Afectados:*  
  - 192.168.122.187:8080/tcp → nginx 1.4.0  
  - 192.168.122.187:8443/tcp → nginx 1.4.0  
- *Versión Instalada:* 1.4.0  
- *Versión Fija:* 1.17.7  
- *Referencia CVE:* CVE-2019-20372  
- *Referencias adicionales:*  
  - http://www.nessus.org/u?fd026623  
  - XREF: IAVB:2020-B-0013-S  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)  
- *VPR:* 2.2  
- *EPSS:* 0.7147  

=== Acciones Recomendadas
1. *Actualizar nginx:* Migrar a la versión 1.17.7 o superior en todos los servicios expuestos.  
2. *Validar Configuración:* Revisar encabezados de respuesta y ocultar información sensible (ej. versión del servidor).  
3. *Segmentar Exposición:* Restringir el acceso a los servicios internos y exponer solo lo estrictamente necesario.  
4. *Monitorear Accesos:* Vigilar intentos de enumeración y exploración de los servicios en 8080/8443.  

*Conclusión:* El uso de *nginx 1.4.0 obsoleto* en *dos servicios web expuestos* representa un riesgo de *reconocimiento y fuga de información*. Aunque su severidad es media, se recomienda una *actualización pronta* para reducir la superficie de ataque y cumplir con buenas prácticas de seguridad.  

== VULN-B020

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *ISC BIND 9.4.2* en el puerto *53/udp (DNS)*. Esta versión es vulnerable a un *Service Downgrade* y a ataques de *Denegación de Servicio Reflejada (Reflected DoS)* (CVE-2020-8616).  
*Riesgo para el Negocio:* Un atacante remoto no autenticado puede degradar el rendimiento del servidor DNS recursivo o utilizarlo como *amplificador en un ataque de reflexión*, lo que puede interrumpir servicios críticos o ser explotado para lanzar ataques distribuidos hacia terceros.  
*Urgencia:* *Alta prioridad de actualización.* Aunque no compromete confidencialidad o integridad, el impacto en *disponibilidad* es severo, y el servidor puede ser explotado en ataques masivos.  
*Acción:* Actualizar inmediatamente a *ISC BIND 9.11.19 o superior* y revisar la configuración del servicio DNS para mitigar abusos.  

=== Análisis Técnico
- *Nombre:* ISC BIND Service Downgrade / Reflected DoS  
- *ID del Plugin:* 136769  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Denegación de Servicio (DoS / Reflection)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:53/udp (DNS)  
- *Versión Instalada:* 9.4.2  
- *Versión Fija:* 9.11.19  
- *Referencia CVE:* CVE-2020-8616  
- *Referencias adicionales:*  
  - https://kb.isc.org/docs/cve-2020-8616  
  - XREF: IAVA:2020-A-0217-S  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v3.0:* 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:N/A:P)  
- *VPR:* 5.2  
- *EPSS:* 0.0334  

=== Acciones Recomendadas
1. *Actualizar BIND:* Instalar la versión 9.11.19 o superior que corrige la vulnerabilidad.  
2. *Configurar Limitaciones:* Habilitar límites en la recursión y en la cantidad de fetches permitidos.  
3. *Mitigar Abuso Externo:* Restringir la recursión a clientes internos confiables para evitar uso en ataques de reflexión.  
4. *Monitorear DNS:* Implementar alertas y análisis de tráfico para detectar patrones de DoS o intentos de explotación.  

*Conclusión:* La versión vulnerable de *ISC BIND* convierte al servidor DNS en un *objetivo crítico* para *ataques de disponibilidad y abuso como reflector*. Se recomienda una *actualización urgente* y endurecer la configuración DNS para evitar explotación.  

== VULN-B021

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *ISC BIND 9.4.2* en el puerto *53/udp (DNS)*, versión vulnerable a un *fallo de aserción* que permite provocar una *denegación de servicio (DoS)* (CVE-2020-8617).  
*Riesgo para el Negocio:* Un atacante remoto y no autenticado puede enviar mensajes especialmente manipulados para hacer que el servicio DNS deje de responder, interrumpiendo la resolución de nombres y afectando la *disponibilidad de servicios críticos*.  
*Urgencia:* *Requiere actualización pronta.* Aunque no compromete datos o integridad, la interrupción del servicio DNS puede tener un *impacto operativo significativo*.  
*Acción:* Actualizar a la versión *ISC BIND 9.11.19 o superior* y aplicar parches oficiales.  

=== Análisis Técnico
- *Nombre:* ISC BIND Denial of Service  
- *ID del Plugin:* 136808  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Denegación de Servicio (Assertion Failure)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:53/udp (DNS)  
- *Versión Instalada:* 9.4.2  
- *Versión Fija:* 9.11.19  
- *Referencia CVE:* CVE-2020-8617  
- *Referencias adicionales:*  
  - https://kb.isc.org/docs/cve-2020-8617  
  - XREF: IAVA:2020-A-0217-S  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)  
- *Puntuación Base CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)  
- *VPR:* 4.4  
- *EPSS:* 0.9228  

=== Acciones Recomendadas
1. *Actualizar BIND:* Migrar a la versión 9.11.19 o superior para eliminar la vulnerabilidad.  
2. *Aplicar Políticas de Resiliencia:* Implementar redundancia DNS (servidores secundarios) para reducir impacto en caso de caída.  
3. *Monitorear Logs:* Revisar registros de fallos de BIND en busca de mensajes de aserción o reinicios inesperados.  
4. *Seguridad Perimetral:* Filtrar tráfico sospechoso y aplicar reglas que bloqueen patrones maliciosos de consultas DNS.  

*Conclusión:* La vulnerabilidad *CVE-2020-8617* en *ISC BIND 9.4.2* puede causar *interrupción total del servicio DNS* mediante un ataque remoto. Es esencial *actualizar y fortalecer la resiliencia* del servicio para evitar impactos en la disponibilidad de la infraestructura.  

== VULN-B022

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *ISC BIND 9.4.2* en el puerto *53/udp (DNS)*. Esta versión es vulnerable a una *denegación de servicio (DoS)* causada por un *fallo de aserción* al procesar respuestas truncadas a solicitudes *TSIG-signed* (CVE-2020-8622).  
*Riesgo para el Negocio:* Un atacante remoto autenticado puede forzar que el servidor DNS se detenga mediante paquetes manipulados, lo que compromete la *disponibilidad* del servicio y afecta aplicaciones críticas que dependen de la resolución de nombres.  
*Urgencia:* *Alta prioridad de actualización.* Aunque requiere autenticación, el riesgo de interrupción en servicios de red es significativo.  
*Acción:* Actualizar a *ISC BIND 9.11.22, 9.16.6, 9.17.4 o versiones posteriores*.  

=== Análisis Técnico
- *Nombre:* ISC BIND 9.x < 9.11.22, 9.12.x < 9.16.6, 9.17.x < 9.17.4 DoS  
- *ID del Plugin:* 139915  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Denegación de Servicio (TSIG Assertion Failure)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:53/udp (DNS)  
- *Versión Instalada:* 9.4.2  
- *Versión Fija:* 9.11.22, 9.16.6, 9.17.4 o posterior  
- *Referencia CVE:* CVE-2020-8622  
- *Referencias adicionales:*  
  - https://kb.isc.org/docs/cve-2020-8622  
  - XREF: IAVA:2020-A-0385-S  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)  
- *Puntuación Base CVSS v2.0:* 4.0 (AV:N/AC:L/Au:S/C:N/I:N/A:P)  
- *VPR:* 4.4  
- *EPSS:* 0.0045  

=== Acciones Recomendadas
1. *Actualizar BIND:* Migrar a la versión 9.11.22, 9.16.6, 9.17.4 o superior.  
2. *Revisar Uso de TSIG:* Validar si el servicio depende de *TSIG-signed requests* y aplicar controles adicionales.  
3. *Mitigar Riesgo Interno:* Limitar el acceso de administración DNS a usuarios autorizados y redes internas seguras.  
4. *Resiliencia DNS:* Implementar redundancia (servidores secundarios) para reducir impacto en caso de caída.  

*Conclusión:* La vulnerabilidad *CVE-2020-8622* en *ISC BIND 9.4.2* permite a un atacante autenticado provocar *fallos de servicio mediante respuestas truncadas TSIG*. Se recomienda *actualizar urgentemente* y reforzar la seguridad operativa del servicio DNS.  

== VULN-B023

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* acepta conexiones en el puerto *8443/tcp* utilizando el protocolo *TLS 1.1*, el cual está obsoleto y ya no es soportado por los principales navegadores y proveedores desde marzo de 2020.  
*Riesgo para el Negocio:* El uso de *TLS 1.1* limita el soporte para algoritmos modernos de cifrado y modos autenticados (como *GCM*), debilitando la protección de la confidencialidad e integridad de las comunicaciones. Esto expone al negocio a *incumplimientos normativos*, pérdida de confianza y posibles ataques de downgrade.  
*Urgencia:* *Se requiere una actualización en el corto plazo.* Aunque no es una vulnerabilidad crítica, mantener protocolos inseguros activos representa un *riesgo de cumplimiento y seguridad de la información*.  
*Acción:* Deshabilitar *TLS 1.1* y habilitar únicamente *TLS 1.2 o 1.3* en los servicios expuestos.  

=== Análisis Técnico
- *Nombre:* TLS Version 1.1 Deprecated Protocol  
- *ID del Plugin:* 157288  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Insegura (Protocolo Obsoleto)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:8443/tcp  
- *Versión Obsoleta:* TLS 1.1 habilitado  
- *Normativa Relevante:* RFC 8996 (Deprecation of TLS 1.0/1.1)  
- *Referencias:*  
  - https://datatracker.ietf.org/doc/html/rfc8996  
  - http://www.nessus.org/u?c8ae820d  
  - CWE-327 (Uso de algoritmos criptográficos inseguros)  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 6.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N)  
- *Puntuación Base CVSS v2.0:* 6.1 (AV:N/AC:H/Au:N/C:C/I:P/A:N)  

=== Acciones Recomendadas
1. *Deshabilitar TLS 1.1:* Configurar el servidor para que solo acepte *TLS 1.2 y TLS 1.3*.  
2. *Verificar Compatibilidad:* Probar las aplicaciones cliente para asegurar compatibilidad con protocolos modernos.  
3. *Cumplimiento Normativo:* Adoptar buenas prácticas de cifrado alineadas con PCI DSS, NIST y OWASP.  
4. *Monitorear Seguridad:* Implementar escaneos periódicos para verificar que protocolos obsoletos permanezcan deshabilitados.  

*Conclusión:* La presencia de *TLS 1.1 habilitado* en el servicio expuesto por *192.168.122.187:8443* es un *riesgo de cumplimiento y cifrado débil*. Se recomienda su *desactivación inmediata* y habilitar únicamente *TLS 1.2/1.3* para garantizar comunicaciones seguras.  

== VULN-B024

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* presenta múltiples servicios con *certificados SSL caducados*, incluyendo *SMTP (25/tcp)*, *HTTPS (443/tcp, 8443/tcp, 9443/tcp)* y *PostgreSQL (5432/tcp)*.  
*Riesgo para el Negocio:* El uso de certificados expirados invalida la confianza en las conexiones seguras, expone a los usuarios a *ataques de intermediario (MITM)* y representa un *incumplimiento de normativas de seguridad y buenas prácticas*. Esto afecta tanto la *confidencialidad* como la *integridad* de la comunicación.  
*Urgencia:* *Requiere atención prioritaria.* Aunque no es un fallo crítico en sí mismo, reduce significativamente la confianza de los clientes y puede habilitar ataques de interceptación.  
*Acción:* Renovar y reemplazar todos los certificados SSL expirados con versiones válidas emitidas por una *Autoridad de Certificación confiable*.  

=== Análisis Técnico
- *Nombre:* SSL Certificate Expiry  
- *ID del Plugin:* 15901  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Criptográfica (Certificados Expirados)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios y Certificados Expirados:*  
  - 25/tcp (SMTP) – Certificado caducado (2010 / 2013)  
  - 443/tcp (HTTPS) – CN=bee-box.bwapp.local, expirado en 2018  
  - 5432/tcp (PostgreSQL) – CN=ubuntu804-base.localdomain, expirado en 2010  
  - 8443/tcp (HTTPS) – CN=bee-box.bwapp.local, expirado en 2018  
  - 9443/tcp (HTTPS) – CN=bee-box.bwapp.local, expirado en 2018  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)  

=== Acciones Recomendadas
1. *Renovación de Certificados:* Emitir nuevos certificados válidos para todos los servicios afectados.  
2. *Uso de AC Confiable:* Adquirir certificados de una Autoridad de Certificación (CA) confiable en lugar de auto-firmados.  
3. *Rotación Periódica:* Implementar procesos de renovación automática o alertas para evitar caducidad futura.  
4. *Pruebas de Compatibilidad:* Verificar que los nuevos certificados funcionen correctamente en todos los servicios (SMTP, HTTPS, PostgreSQL).  
5. *Cumplimiento Normativo:* Alinear la gestión de certificados con estándares PCI DSS, NIST y OWASP.  

*Conclusión:* Los *certificados SSL caducados en múltiples servicios críticos* exponen al servidor a *riesgos de interceptación y pérdida de confianza*. Se requiere una *renovación inmediata* de los certificados y la adopción de políticas de gestión de ciclo de vida de certificados digitales.  

== VULN-B025

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* soporta *suites de cifrado SSL débiles* en varios servicios (*SMTP 25/tcp, HTTPS 443/tcp, HTTPS 9443/tcp*). Estos cifrados utilizan claves de baja longitud (≤ 64 bits) y algoritmos inseguros como *RC2, RC4 y DES*.  
*Riesgo para el Negocio:* El uso de cifrados débiles permite que un atacante con capacidad de interceptar tráfico (especialmente en la misma red) pueda *descifrar o manipular comunicaciones*. Esto degrada la *confidencialidad e integridad* de los datos y representa un *riesgo de cumplimiento normativo*.  
*Urgencia:* *Requiere atención prioritaria.* Aunque no es trivial explotarlo a gran escala, el mantenimiento de cifrados débiles abre la puerta a ataques de *downgrade* y *criptoanálisis*.  
*Acción:* Deshabilitar cifrados inseguros y configurar el uso exclusivo de suites modernas (AES con GCM/ChaCha20, TLS 1.2/1.3).  

=== Análisis Técnico
- *Nombre:* SSL Weak Cipher Suites Supported  
- *ID del Plugin:* 26928  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Criptográfica (Cifrados Débiles)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios y Cifrados Débiles Detectados:*  
  - 25/tcp (SMTP) → Soporta RC2-CBC(40), RC4(40), DES(40–56), MD5, SHA1  
  - 443/tcp (HTTPS) → Soporta RC2, RC4, DES (≤ 56 bits), MD5  
  - 9443/tcp (HTTPS) → Soporta RC2, RC4, DES débiles  
- *Ejemplos de Cifrados inseguros:*  
  - EXP-RC2-CBC-MD5 (40-bit, export)  
  - EXP-RC4-MD5 (40-bit, export)  
  - DES-CBC-SHA (56-bit)  
  - ADH/EDH con claves ≤ 512 bits  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)  

*Referencias:*  
- http://www.nessus.org/u?6527892d  
- CWE-326, CWE-327, CWE-720, CWE-753, CWE-803, CWE-928, CWE-934  

=== Acciones Recomendadas
1. *Deshabilitar Cifrados Débiles:* Modificar la configuración de OpenSSL/servicios afectados para excluir RC2, RC4, DES y MD5.  
2. *Forzar Cifrados Fuertes:* Permitir únicamente AES (128/256) con GCM o ChaCha20, en TLS 1.2/1.3.  
3. *Cumplimiento Normativo:* Adoptar políticas alineadas con NIST y PCI DSS (que requieren deshabilitar cifrados inseguros).  
4. *Pruebas de Compatibilidad:* Validar que los clientes soporten protocolos modernos antes de deshabilitar los débiles.  
5. *Escaneos Periódicos:* Realizar auditorías regulares para confirmar que no se reactiven suites débiles.  

*Conclusión:* La habilitación de *cifrados SSL inseguros en múltiples servicios críticos* expone al servidor a *ataques de descifrado y downgrade*. Se recomienda su *eliminación inmediata* y reforzar la configuración de TLS con suites criptográficas modernas.  

== VULN-B026

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* presenta múltiples servicios (*443/tcp, 8443/tcp, 9443/tcp*) con *certificados SSL firmados usando algoritmos débiles* (SHA-1). Este algoritmo criptográfico es vulnerable a *ataques de colisión* y ha sido desaprobado por la industria desde 2017.  
*Riesgo para el Negocio:* Un atacante podría generar un certificado fraudulento con la misma firma digital, lo que permitiría *suplantar el servicio* afectado y ejecutar ataques de *man-in-the-middle (MITM)* o falsificación de identidad. Además, mantener SHA-1 incumple buenas prácticas de seguridad y estándares regulatorios.  
*Urgencia:* *Atención prioritaria.* Aunque no es trivial generar colisiones efectivas en corto plazo, su uso está obsoleto y *no cumple con estándares modernos de seguridad*.  
*Acción:* Reemitir los certificados SSL con algoritmos seguros (*SHA-256 o superior*) a través de una *Autoridad de Certificación confiable*.  

=== Análisis Técnico
- *Nombre:* SSL Certificate Signed Using Weak Hashing Algorithm  
- *ID del Plugin:* 35291  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Criptográfica (Firma Débil en Certificados)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios y Certificados Afectados:*  
  - 443/tcp → CN=bee-box.bwapp.local, firmado con SHA-1 (2013–2018)  
  - 8443/tcp → CN=bee-box.bwapp.local, firmado con SHA-1 (2013–2018)  
  - 9443/tcp → CN=bee-box.bwapp.local, firmado con SHA-1 (2013–2018)  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)  
- *VPR:* 4.2  
- *EPSS:* 0.0815  

*Referencias:*  
- RFC 3279 (X.509 Algorithms)  
- CVE-2004-2761, CVE-2005-4900  
- BID: 11849, 33065  
- CWE-310 (Uso de algoritmos criptográficos inseguros)  

=== Acciones Recomendadas
1. *Reemitir Certificados:* Solicitar a la CA nuevos certificados usando *SHA-256 o superior*.  
2. *Eliminar SHA-1:* Asegurarse de que ningún servicio acepte certificados con SHA-1.  
3. *Política de Certificados:* Implementar monitoreo de vigencia y algoritmos usados en certificados.  
4. *Cumplimiento:* Adoptar lineamientos de NIST y OWASP sobre uso exclusivo de algoritmos seguros.  
5. *Rotación Planificada:* Establecer renovación periódica de certificados con alertas preventivas.  

*Conclusión:* La presencia de *certificados firmados con SHA-1* en servicios críticos expone al host a *riesgos de suplantación y MITM*. Se recomienda *reemplazarlos inmediatamente* por certificados con algoritmos modernos como *SHA-256 o superiores*.  

== VULN-B027

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* expone *NFS shares sin restricciones de acceso* en el puerto *2049/tcp*. Esto significa que cualquier cliente puede leer el contenido de los directorios exportados sin necesidad de autenticación ni validación de origen.  
*Riesgo para el Negocio:* La exposición de *NFS world-readable* representa una amenaza crítica de *filtración de información sensible*. Un atacante podría acceder a datos confidenciales, recolectar información del sistema y preparar ataques posteriores de mayor impacto.  
*Urgencia:* *Corrección inmediata requerida.* NFS sin control de acceso es una *mala práctica crítica de configuración* y debe corregirse cuanto antes.  
*Acción:* Configurar restricciones de acceso en el * /etc/exports*, permitiendo únicamente clientes de confianza, y deshabilitar la exportación global.  

=== Análisis Técnico
- *Nombre:* NFS Shares World Readable  
- *ID del Plugin:* 42256  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Configuración Insegura (Acceso Global a Recursos)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:2049/tcp (NFS)  
- *Shares Exportados sin Restricción:*  
- * / * (world-readable)  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v3.0:* 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  

*Referencia:*  
- http://www.tldp.org/HOWTO/NFS-HOWTO/security.html  

=== Acciones Recomendadas
1. *Restringir Acceso:* Configurar *hosts permitidos* en * /etc/exports* (ejemplo: `192.168.122.0/24(rw,sync,no_root_squash)`).  
2. *Revisar Permisos:* Asegurar que los directorios exportados solo contengan datos que realmente deban compartirse.  
3. *Monitorear Conexiones:* Implementar registros y auditoría de accesos a NFS.  
4. *Alternativas Seguras:* Usar mecanismos modernos de compartición con control de acceso fuerte (ejemplo: SMB con autenticación, NFSv4 con Kerberos).  

*Conclusión:* La configuración de *NFS sin restricciones* permite acceso global a directorios exportados, exponiendo datos sensibles y aumentando la superficie de ataque. Se recomienda *corregir inmediatamente la configuración de NFS* para limitar el acceso únicamente a clientes autorizados.  

== VULN-B028

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta un servicio de *Telnet en el puerto 23/tcp* que transmite credenciales y comandos en *texto claro*.  
*Riesgo para el Negocio:* La transmisión de credenciales sin cifrar permite a un atacante realizar *ataques de intermediario (MITM)* para capturar usuarios y contraseñas, así como modificar tráfico en tránsito. Esto compromete la *confidencialidad* y la *integridad* de la información. Además, el uso de Telnet incumple con estándares modernos de seguridad y normativas de cumplimiento.  
*Urgencia:* *Corrección inmediata requerida.* El uso de Telnet en entornos de producción es inseguro y debe ser reemplazado.  
*Acción:* Deshabilitar el servicio *Telnet* y migrar a *SSH*, que provee autenticación segura y cifrado de extremo a extremo.  

=== Análisis Técnico
- *Nombre:* Unencrypted Telnet Server  
- *ID del Plugin:* 42263  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Servicio Inseguro (Texto Claro)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:23/tcp (Telnet)  
- *Comportamiento Observado:*  
  - Transmisión de credenciales y comandos sin cifrado  
  - Banner expuesto con advertencia de no usar en redes inseguras  
- *Consecuencias:*  
  - Robo de credenciales mediante sniffing  
  - Posible manipulación de sesiones  
  - Compromiso total del sistema si se obtiene acceso  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)  
- *Puntuación Base CVSS v2.0:* 5.8 (AV:N/AC:M/Au:N/C:P/I:P/A:N)  

=== Acciones Recomendadas
1. *Deshabilitar Telnet:* Eliminar o detener el servicio Telnet en el sistema.  
2. *Migrar a SSH:* Implementar *SSH (Secure Shell)* para acceso remoto con cifrado seguro.  
3. *Revisar Configuración de Acceso:* Asegurar que solo usuarios autorizados tengan permisos de conexión remota.  
4. *Monitorear Intentos:* Auditar conexiones para identificar intentos de uso indebido de Telnet.  
5. *Cumplimiento:* Alinear la política de accesos remotos con estándares de seguridad (ej. NIST, CIS Benchmarks).  

*Conclusión:* El uso de *Telnet sin cifrado* representa una *falla crítica de seguridad en el control de accesos remotos*. Se recomienda *deshabilitarlo de inmediato* y migrar a *SSH* para proteger credenciales y comunicaciones.  

== VULN-B029

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* soporta *cifrados SSL de fuerza media* en múltiples servicios (*SMTP 25/tcp, HTTPS 443/tcp, PostgreSQL 5432/tcp, HTTPS 8443/tcp, HTTPS 9443/tcp*). Esto incluye el uso de *3DES (Triple DES)*, afectado por la vulnerabilidad conocida como *SWEET32* (CVE-2016-2183).  
*Riesgo para el Negocio:* El uso de cifrados de fuerza media debilita la protección de datos en tránsito. Un atacante en la misma red podría explotar *SWEET32* para recuperar información sensible de sesiones cifradas, comprometiendo la *confidencialidad*. Además, mantener cifrados obsoletos incumple con buenas prácticas y normativas (PCI DSS, NIST).  
*Urgencia:* *Alta prioridad de mitigación.* Aunque no es un ataque trivial, la exposición de 3DES es considerada insegura y debe eliminarse.  
*Acción:* Deshabilitar *3DES y cifrados de fuerza media* en todos los servicios, permitiendo únicamente cifrados modernos (*AES-GCM, ChaCha20*) bajo *TLS 1.2/1.3*.  

=== Análisis Técnico
- *Nombre:* SSL Medium Strength Cipher Suites Supported (SWEET32)  
- *ID del Plugin:* 42873  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Configuración Criptográfica (Cifrado Obsoleto – 3DES)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios Afectados:*  
  - 25/tcp (SMTP) – soporta 3DES-CBC con MD5/SHA1  
  - 443/tcp (HTTPS) – soporta 3DES-CBC (168-bit)  
  - 5432/tcp (PostgreSQL) – soporta 3DES-CBC (168-bit)  
  - 8443/tcp (HTTPS) – soporta 3DES-CBC (168-bit)  
  - 9443/tcp (HTTPS) – soporta 3DES-CBC (168-bit)  
- *Ejemplo de Cifrados inseguros detectados:*  
  - DES-CBC3-MD5  
  - EDH-RSA-DES-CBC3-SHA  
  - ADH-DES-CBC3-SHA  
  - DES-CBC3-SHA  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v3.0:* 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  
- *VPR:* 6.1  
- *EPSS:* 0.2879  

*Referencias:*  
- https://sweet32.info  
- http://www.nessus.org/u?df5555f5  
- CVE-2016-2183  

=== Acciones Recomendadas
1. *Eliminar 3DES:* Reconfigurar OpenSSL y servicios afectados para deshabilitar 3DES y cifrados ≤ 112 bits.  
2. *Habilitar Cifrados Seguros:* Usar únicamente AES-GCM (128/256) o ChaCha20 en TLS 1.2/1.3.  
3. *Cumplimiento:* Alinear políticas con PCI DSS v3.2.1 y NIST SP 800-52r2, que desaconsejan 3DES.  
4. *Pruebas de Compatibilidad:* Validar que clientes y aplicaciones soporten cifrados modernos antes de deshabilitar 3DES.  
5. *Monitoreo Regular:* Realizar escaneos periódicos para asegurar que no se reactivan suites inseguras.  

*Conclusión:* La presencia de *cifrados SSL de fuerza media (3DES – SWEET32)* en múltiples servicios representa un *riesgo alto de confidencialidad*. Se recomienda *deshabilitar inmediatamente 3DES* y forzar el uso de *TLS 1.2/1.3 con cifrados modernos*.  

== VULN-B030

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta un servicio *NTP vulnerable* en el puerto *123/udp*. La versión de *ntpd* es afectada por una falla que permite un *bucle infinito de respuestas de error Mode 7*, generando una condición de *Denegación de Servicio (DoS)* (CVE-2009-3563).  
*Riesgo para el Negocio:* Un atacante remoto puede enviar paquetes especialmente manipulados con direcciones IP falsificadas para provocar que el servidor NTP consuma *recursos de CPU de forma indefinida*. Esto puede afectar la *disponibilidad* de servicios críticos que dependan de sincronización de tiempo precisa.  
*Urgencia:* *Requiere actualización prioritaria.* Aunque el impacto es principalmente en disponibilidad, la facilidad de explotación lo convierte en un riesgo operativo importante.  
*Acción:* Actualizar a *NTP 4.2.4p8, 4.2.6 o posterior*.  

=== Análisis Técnico
- *Nombre:* NTP ntpd Mode 7 Error Response Packet Loop Remote DoS  
- *ID del Plugin:* 43156  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Denegación de Servicio (bucle de respuestas NTP)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187:123/udp (NTP)  
- *Comportamiento Vulnerable:* ntpd responde a sus propios paquetes *Mode 7 error*, generando un bucle infinito y saturación de CPU.  
- *Versión Segura:* NTP 4.2.4p8, 4.2.6 o posterior  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v2.0:* 6.4 (AV:N/AC:L/Au:N/C:N/I:P/A:P)  
- *VPR:* 3.6  
- *EPSS:* 0.8693  

*Referencias:*  
- CVE-2009-3563  
- https://bugs.ntp.org/show_bug.cgi?id=1331  
- http://www.nessus.org/u?3a07ed05  
- BID: 37255  
- CERT:568372  
- Secunia:37629  

=== Acciones Recomendadas
1. *Actualizar NTP:* Instalar la versión 4.2.4p8, 4.2.6 o superior.  
2. *Filtrar Tráfico NTP:* Restringir el acceso al puerto UDP/123 desde redes no confiables.  
3. *Monitorear Recursos:* Implementar alertas de consumo anómalo de CPU en el servicio ntpd.  
4. *Seguridad de Red:* Usar firewalls y ACLs para limitar el uso de NTP únicamente a clientes autorizados.  

*Conclusión:* La vulnerabilidad *CVE-2009-3563* en *ntpd* permite un ataque trivial de *Denegación de Servicio por bucle infinito de paquetes Mode 7*. Se recomienda una *actualización inmediata* y aplicar controles de red para evitar explotación.  

== VULN-B031

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* utiliza *certificados SSL con nombres de host incorrectos* en múltiples servicios (*SMTP 25/tcp, HTTPS 443/tcp, PostgreSQL 5432/tcp, HTTPS 8443/tcp, HTTPS 9443/tcp*). El *Common Name (CN)* de los certificados no coincide con la identidad real del servidor.  
*Riesgo para el Negocio:* Los clientes que validan certificados pueden mostrar *advertencias de seguridad* o rechazar conexiones, lo que afecta la *confianza de los usuarios* y la *compatibilidad con aplicaciones*. Además, el desajuste facilita ataques de *suplantación (MITM)*, ya que los usuarios pueden ignorar advertencias y conectarse a servidores maliciosos.  
*Urgencia:* *Alta prioridad de corrección.* Si bien no implica una explotación directa del cifrado, expone a fallos de autenticidad y posibles ataques de interceptación.  
*Acción:* Generar e instalar certificados SSL válidos con nombres de host que coincidan con las direcciones o dominios de servicio reales.  

=== Análisis Técnico
- *Nombre:* SSL Certificate with Wrong Hostname  
- *ID del Plugin:* 45411  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Criptográfica (Hostname Mismatch)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios Afectados:*  
  - 25/tcp (SMTP) → CN=ubuntu804-base.localdomain / CN=ubuntu  
  - 443/tcp (HTTPS) → CN=bee-box.bwapp.local  
  - 5432/tcp (PostgreSQL) → CN=ubuntu804-base.localdomain  
  - 8443/tcp (HTTPS) → CN=bee-box.bwapp.local  
  - 9443/tcp (HTTPS) → CN=bee-box.bwapp.local  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)  

=== Acciones Recomendadas
1. *Emitir Nuevos Certificados:* Solicitar certificados SSL con CN y/o SAN (Subject Alternative Name) que coincidan con los nombres de host o dominios reales de cada servicio.  
2. *Eliminar Certificados Incorrectos:* Retirar certificados con nombres inválidos o genéricos.  
3. *Verificación de Conexiones:* Probar con navegadores y clientes de correo/DB para confirmar que no se generen advertencias.  
4. *Cumplimiento:* Alinear gestión de certificados con OWASP ASVS y NIST SP 800-52.  
5. *Automatización:* Implementar procesos de renovación y validación periódica de certificados.  

*Conclusión:* Los *certificados SSL con nombres de host incorrectos* comprometen la *confianza y autenticidad* de las conexiones. Se recomienda *emitir y desplegar certificados válidos inmediatamente* para todos los servicios afectados.  

== VULN-B032

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* presenta *certificados SSL no confiables* en múltiples servicios (*SMTP 25/tcp, HTTPS 443/tcp, PostgreSQL 5432/tcp, HTTPS 8443/tcp, HTTPS 9443/tcp*). Estos certificados son *autofirmados, expirados* o firmados por *autoridades no reconocidas*.  
*Riesgo para el Negocio:* El uso de certificados no confiables rompe la *cadena de confianza*, lo que expone a los usuarios a *ataques de intermediario (MITM)* y compromete la *autenticidad de los servicios*. Clientes y navegadores modernos rechazarán las conexiones o mostrarán advertencias críticas, afectando *usabilidad y cumplimiento*.  
*Urgencia:* *Alta prioridad de corrección.* El uso de certificados autofirmados y caducados no es aceptable en entornos productivos.  
*Acción:* Adquirir e implementar certificados válidos de una *Autoridad de Certificación confiable* y configurar adecuadamente la cadena de confianza.  

=== Análisis Técnico
- *Nombre:* SSL Certificate Cannot Be Trusted  
- *ID del Plugin:* 51192  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración Criptográfica (Certificados autofirmados / caducados)  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios Afectados:*  
  - 25/tcp (SMTP) – Certificados autofirmados y expirados  
  - 443/tcp (HTTPS) – CN=bee-box.bwapp.local, expirado y no confiable  
  - 5432/tcp (PostgreSQL) – Certificados autofirmados y expirados  
  - 8443/tcp (HTTPS) – CN=bee-box.bwapp.local, expirado y no confiable  
  - 9443/tcp (HTTPS) – CN=bee-box.bwapp.local, expirado y no confiable  

*Ejemplos de Problemas Detectados:*  
- Certificados con fechas de expiración superadas (*2010, 2013, 2018*).  
- Certificados autofirmados sin una CA reconocida.  
- Cadenas de confianza incompletas o inválidas.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)  
- *Puntuación Base CVSS v2.0:* 6.4 (AV:N/AC:L/Au:N/C:P/I:P/A:N)  

*Referencias:*  
- https://www.itu.int/rec/T-REC-X.509/en  
- https://en.wikipedia.org/wiki/X.509  

=== Acciones Recomendadas
1. *Emitir Certificados Válidos:* Solicitar certificados firmados por una Autoridad de Certificación confiable (CA pública o interna).  
2. *Renovación Periódica:* Implementar procesos de renovación automática para evitar expiraciones.  
3. *Cadena de Confianza Completa:* Incluir certificados intermedios válidos en la configuración del servidor.  
4. *Pruebas de Validación:* Verificar con navegadores y clientes para confirmar la eliminación de advertencias.  
5. *Cumplimiento:* Alinear políticas con OWASP ASVS y NIST SP 800-52r2 sobre gestión de certificados digitales.  

*Conclusión:* Los *certificados SSL no confiables* en múltiples servicios representan un *riesgo de MITM y pérdida de confianza*. Se recomienda *sustituir de inmediato todos los certificados autofirmados o expirados* por certificados válidos de una CA reconocida.  

== VULN-B033

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta un servicio *SMTP (25/tcp)* vulnerable a *inyección de comandos en texto plano durante la negociación STARTTLS*. Esto permite a un atacante inyectar comandos en la fase inicial de comunicación antes de que el canal cifrado esté establecido.  
*Riesgo para el Negocio:* La explotación puede derivar en *robo de credenciales SASL*, *interceptación de correos electrónicos* o manipulación de comandos SMTP, comprometiendo la *confidencialidad* y la *integridad de la comunicación*.  
*Urgencia:* *Alta*, debido a que afecta un servicio crítico como correo electrónico y puede ser explotado sin autenticación previa.  
*Acción:* Aplicar parches o actualizaciones del software SMTP afectados, y considerar deshabilitar STARTTLS en versiones vulnerables.  

=== Análisis Técnico
- *Nombre:* SMTP Service STARTTLS Plaintext Command Injection  
- *ID del Plugin:* 52611  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración / Implementación Criptográfica  
- *Publicado:* 2011  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Puerto Afectado:* 25/tcp (SMTP)  
- *Detalles de Explotación:*  
  - Comandos inyectados durante fase *plaintext*: `STARTTLS\r\nRSET\r\n`  
  - Respuesta aceptada por el servidor → `220 Ready to start TLS` y `250 Ok`.  
- *Posible Impacto:* Robo de credenciales, manipulación de correo, acceso no autorizado.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v2.0:* 4.0 (AV:N/AC:H/Au:N/C:P/I:P/A:N)  
- *Puntuación VPR:* 7.3  
- *EPSS:* 0.6945 (probabilidad de explotación elevada)  

*Referencias:*  
- RFC 2487: STARTTLS  
- CVE-2011-0411, CVE-2011-1430, CVE-2011-1431, CVE-2011-1432, CVE-2011-1506, CVE-2011-2165  
- CERT:555316  

=== Acciones Recomendadas
1. *Actualizar el Servidor SMTP:* Instalar parches que corrijan el fallo en la implementación STARTTLS.  
2. *Configurar Seguridad Adicional:* Deshabilitar STARTTLS inseguro y reforzar uso de TLS 1.2/1.3.  
3. *Monitorear Logs SMTP:* Revisar registros en busca de intentos de inyección o explotación.  
4. *Revisar Configuración de SASL:* Implementar autenticación robusta y cifrado obligatorio.  
5. *Cumplimiento:* Alinear prácticas con guías de seguridad de correo de OWASP y NIST.  

*Conclusión:* El *SMTP STARTTLS vulnerable* en el host *192.168.122.187* permite *inyección de comandos antes del cifrado*, comprometiendo la seguridad del correo electrónico. Se recomienda *parchear y reforzar la configuración de inmediato*.  

== VULN-B034

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* expone múltiples servicios (*SMTP, PostgreSQL, HTTPS en 443/8443/9443*) con *certificados SSL autofirmados*. Estos no están emitidos por una Autoridad de Certificación (CA) confiable.  
*Riesgo para el Negocio:* Cualquier atacante podría establecer ataques *Man-in-the-Middle (MITM)*, ya que los clientes no pueden validar la legitimidad del servidor. Esto invalida el propósito del cifrado SSL en entornos productivos.  
*Urgencia:* *Alta* para servicios expuestos a internet.  
*Acción:* Sustituir todos los certificados autofirmados por certificados válidos emitidos por una CA de confianza.  

=== Análisis Técnico
- *Nombre:* SSL Self-Signed Certificate  
- *ID del Plugin:* 57582  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Criptografía / Certificados  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicios Afectados:*  
  - *SMTP (25/tcp)*  
  - *PostgreSQL (5432/tcp)*  
  - *HTTPS (443, 8443, 9443/tcp)*  
- *Certificados detectados:*  
  - CN=ubuntu804-base.localdomain (autofirmado)  
  - CN=ubuntu (autofirmado)  
  - CN=bee-box.bwapp.local (autofirmado)  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *CVSS v3.0:* 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)  
- *CVSS v2.0:* 6.4 (AV:N/AC:L/Au:N/C:P/I:P/A:N)  
- *VPR:* No aplica  
- *EPSS:* No aplica  

*Referencias:*  
- X.509 Standard: https://www.itu.int/rec/T-REC-X.509/en  

=== Acciones Recomendadas
1. *Emitir Certificados Válidos:* Generar certificados firmados por una CA pública o por una CA corporativa interna reconocida.  
2. *Deshabilitar Certificados Autofirmados:* Eliminar certificados no confiables de los servicios.  
3. *Implementar TLS Moderno:* Usar versiones TLS 1.2/1.3 y deshabilitar suites débiles.  
4. *Verificar Cadena de Confianza:* Configurar correctamente certificados intermedios en los servicios afectados.  
5. *Cumplimiento:* Alinear con mejores prácticas de seguridad en comunicaciones (OWASP, NIST).  

*Conclusión:* El uso de *certificados SSL autofirmados* en servicios críticos (*SMTP, PostgreSQL, HTTPS*) expone al host *192.168.122.187* a ataques de *suplantación y MITM*. Se recomienda reemplazarlos inmediatamente con certificados válidos emitidos por una CA.  

== VULN-B035

=== Resumen Ejecutivo
*Problema:* El servidor *SMB (445/tcp)* en el host *192.168.122.187* no requiere *firma digital (SMB signing)* para la comunicación.  
*Riesgo para el Negocio:* Permite a un atacante *interceptar o modificar tráfico SMB* mediante ataques *Man-in-the-Middle (MITM)*, comprometiendo la integridad de los datos compartidos.  
*Urgencia:* Media, especialmente crítico si el servicio SMB está expuesto fuera de la red interna.  
*Acción:* Habilitar y forzar *SMB signing* en la configuración del servidor Samba o Windows.  

=== Análisis Técnico
- *Nombre:* SMB Signing not required  
- *ID del Plugin:* 57608  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Configuración débil / Protocolos de autenticación  
- *Publicado:* —  
- *Modificado:* —  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Servicio Afectado:* SMB (445/tcp, CIFS)  
- *Vector de Ataque:* Un atacante en la red puede alterar paquetes SMB sin detección.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)  
- *CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)  
- *VPR:* No aplica  
- *EPSS:* No aplica  

*Referencias:*  
- Microsoft Technet – SMB Signing: http://technet.microsoft.com/en-us/library/cc731957.aspx  
- Samba Documentation: https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html  

=== Acciones Recomendadas
1. *Configurar Firma Obligatoria:*  
   - En *Windows*: habilitar la política **"Microsoft network server: Digitally sign communications (always)"**.  
   - En *Samba*: establecer `server signing = mandatory` en smb.conf.  
2. *Restringir Acceso SMB:* Limitar acceso a SMB solo desde redes internas confiables.  
3. *Monitorear Tráfico:* Implementar IDS/IPS para detectar intentos de MITM sobre SMB.  
4. *Migrar a Versiones Seguras:* Evitar versiones antiguas de SMB, priorizar SMBv3.  

*Conclusión:* La ausencia de *SMB signing* en *192.168.122.187* expone la integridad de las comunicaciones y datos compartidos. Se recomienda activar de inmediato la firma digital obligatoria para mitigar ataques de manipulación de tráfico SMB.  

== VULN-B036

=== Resumen Ejecutivo
*Problema:* El servidor en *192.168.122.187* soporta *cifrados RC4* en múltiples servicios (SMTP, HTTPS, PostgreSQL, puertos 25/443/5432/9443).  
*Riesgo para el Negocio:* El algoritmo *RC4* está roto: genera sesgos predecibles en el flujo pseudoaleatorio, lo que permite a un atacante deducir texto plano a partir de grandes volúmenes de tráfico cifrado (ej. cookies o credenciales).  
*Urgencia:* Media–Alta. Aunque la explotación requiere millones de capturas, RC4 está obsoleto y no cumple normativas de seguridad modernas (PCI-DSS, NIST, ISO/IEC 27001).  
*Acción:* Deshabilitar todos los cifrados RC4 y migrar a suites TLS modernas (TLS 1.2+ con AES-GCM o ChaCha20-Poly1305).  

=== Análisis Técnico
- *Nombre:* SSL RC4 Cipher Suites Supported (Bar Mitzvah)  
- *ID del Plugin:* 65821  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Criptografía débil  
- *Servicios afectados:*  
  - SMTP (tcp/25)  
  - HTTPS (tcp/443, tcp/9443, tcp/8443)  
  - PostgreSQL (tcp/5432)  

*Impacto:*  
- Posibilidad de ataques de recuperación de texto plano sobre comunicaciones persistentes.  
- Riesgo incrementado si se transmiten *cookies de sesión, credenciales o datos sensibles*.  
- Compatibilidad con navegadores modernos comprometida, ya que RC4 ha sido eliminado de Chrome, Firefox, Edge, etc.  

*Puntuación de Riesgo:*  
- *CVSS v3.0:* 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)  
- *CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  
- *VPR:* 7.3  
- *EPSS:* 0.9267 (alta probabilidad de explotación)  

*Referencias:*  
- [RC4 No More](https://www.rc4nomore.com/)  
- [Imperva – Attacking SSL with RC4](https://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf)  
- CVEs relacionados: CVE-2013-2566, CVE-2015-2808  

=== Acciones Recomendadas
1. *Deshabilitar RC4* en todas las configuraciones de servicios (SMTP, HTTPS, PostgreSQL, Nginx/Apache, OpenSSL, Postfix, etc.).  
2. *Migrar a TLS 1.2 o TLS 1.3* con suites seguras (AES-GCM, ChaCha20-Poly1305).  
3. *Actualizar librerías criptográficas* (OpenSSL ≥ 1.1.1, GnuTLS, etc.).  
4. *Revisar cumplimiento normativo*: PCI-DSS 3.2.1 y NIST 800-52 prohíben explícitamente el uso de RC4.  

*Conclusión:* El uso de *RC4* en *192.168.122.187* expone las comunicaciones a ataques criptográficos prácticos. Su eliminación es prioritaria para garantizar comunicaciones seguras y cumplimiento de estándares.  

== VULN-B037

=== Resumen Ejecutivo
*Problema:* El servicio *NTP (udp/123)* en el host *192.168.122.187* tiene habilitado el comando *monlist*.  
*Riesgo para el Negocio:* Este comando permite a un atacante remoto realizar ataques de *amplificación y reflexión* (DDoS), aprovechando el servidor como vector para saturar a terceros. Además, puede usarse para *reconocimiento* al revelar direcciones IP que interactuaron con el servidor.  
*Urgencia:* Alta. Los ataques de reflexión NTP son ampliamente usados en campañas DDoS globales.  
*Acción:* Deshabilitar el comando *monlist* (añadiendo `disable monitor` en *ntp.conf*) o actualizar a *NTP 4.2.7p26* o posterior.  

=== Análisis Técnico
- *Nombre:* NTP Daemon monlist Command Enabled DoS  
- *ID del Plugin:* 71783  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Puerto afectado:* udp/123 (NTP)  
- *Sistema operativo:* Linux Kernel 2.6 (Ubuntu 8.04 Hardy)  

*Impacto:*  
- Posibilidad de ataques *reflejo y amplificación DDoS*, generando tráfico excesivo contra víctimas externas.  
- Exposición de direcciones IP recientes conectadas al servidor → facilita tareas de *reconocimiento*.  
- Riesgo de indisponibilidad del servicio local por saturación de recursos.  

*Puntuación de Riesgo:*  
- *CVSS v3.0:* 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)  
- *CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:N/A:P)  
- *VPR:* 6.7  
- *EPSS:* 0.9173 (alta probabilidad de explotación)  

*Evidencia:*  
Nessus logró extraer la lista de clientes recientes → `192.168.122.1`.  

*Referencias:*  
- [SANS ISC – NTP Reflection Attacks](https://isc.sans.edu/diary/NTP+reflection+attack/17300)  
- [Bug NTP.org #1532](http://bugs.ntp.org/show_bug.cgi?id=1532)  
- CVE-2013-5211  
- CERT:348126  

=== Acciones Recomendadas
1. *Actualizar NTP* a la versión *4.2.7p26 o superior*.  
2. Si no es posible actualizar, modificar `ntp.conf` y añadir la línea:  

== VULN-B038

=== Resumen Ejecutivo
*Problema:* El servicio *HTTPS (tcp/8443)* en el host *192.168.122.187* es vulnerable a *Heartbleed (CVE-2014-0160)*.  
*Riesgo para el Negocio:* La falla permite a atacantes remotos leer fragmentos de la memoria del servidor (hasta 64KB), lo que puede exponer *credenciales, claves privadas SSL y datos sensibles*. Este tipo de vulnerabilidad compromete directamente la *confidencialidad* y puede llevar a ataques de *robo de identidad digital*, escalamiento y persistencia en sistemas críticos.  
*Urgencia:* Crítica. Heartbleed ha sido ampliamente explotado desde su divulgación y continúa siendo objetivo de pruebas automatizadas.  
*Acción:* Actualizar OpenSSL a la versión *1.0.1g o superior* o recompilar con la bandera `-DOPENSSL_NO_HEARTBEATS`.  

=== Análisis Técnico
- *Nombre:* OpenSSL Heartbeat Information Disclosure (Heartbleed)  
- *ID del Plugin:* 73412  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Puerto afectado:* tcp/8443 (HTTPS)  
- *Sistema operativo:* Linux Kernel 2.6 (Ubuntu 8.04 Hardy)  

*Impacto:*  
- Lectura de hasta *64 KB de memoria* por solicitud maliciosa.  
- Posible exposición de:  
  - *Credenciales de usuario* y sesiones activas.  
  - *Claves privadas TLS*, que comprometen todo el cifrado posterior.  
  - *Datos confidenciales* en memoria de procesos.  
- Facilita ataques de *interceptación (MITM)* y persistencia mediante robo de certificados.  

*Puntuación de Riesgo:*  
- *CVSS v3.0:* 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
- *CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:P/I:N/A:N)  
- *VPR:* 6.1  
- *EPSS:* 0.9444 (alta probabilidad de explotación)  
- *Explotabilidad:* Confirmada → Metasploit y Core Impact disponibles.  

*Evidencia:*  
Nessus demostró la vulnerabilidad al extraer contenido de memoria del servidor durante un *handshake TLS* con mensajes *heartbeat* manipulados.  

*Referencias:*  
- [Heartbleed.com](http://heartbleed.com/)  
- [OpenSSL Advisory](https://www.openssl.org/news/secadv/20140407.txt)  
- CVE-2014-0160  
- CERT:720951  
- CISA KEV Catalog (25/05/2022)  

=== Acciones Recomendadas
1. *Actualizar OpenSSL* a la versión *1.0.1g o superior*.  
2. Como mitigación temporal: recompilar OpenSSL con la bandera `-DOPENSSL_NO_HEARTBEATS`.  
3. *Revocar y regenerar certificados TLS* potencialmente expuestos.  
4. Rotar contraseñas y credenciales que puedan haber sido filtradas.  
5. Implementar monitoreo para detectar intentos de explotación y conexiones sospechosas.  

*Conclusión:* Heartbleed representa una de las vulnerabilidades más críticas de los últimos años. Su explotación compromete directamente la *confidencialidad de datos* y la *integridad del cifrado TLS*. La remediación inmediata es esencial.  

== VULN-B039

=== Resumen Ejecutivo
*Problema:* El servicio *SNMP (udp/161)* en el host *192.168.122.187* permite explotación como *amplificador en ataques DDoS reflejados* mediante solicitudes `GETBULK` maliciosas.  
*Riesgo para el Negocio:* Aunque no compromete directamente la confidencialidad ni la integridad de los sistemas internos, convierte al servidor en un *agente de ataques distribuidos*, lo que puede generar *responsabilidad legal*, *bloqueo de red* por parte de ISPs, o incluso *interrupciones colaterales de servicio*.  
*Urgencia:* Moderada. Si bien no se trata de una vulnerabilidad de acceso directo, la explotación de SNMP como vector DDoS es ampliamente conocida y automatizada.  
*Acción:* Deshabilitar SNMP si no es estrictamente necesario, o aplicar controles de acceso y monitoreo estricto.  

=== Análisis Técnico
- *Nombre:* SNMP `GETBULK` Reflection DDoS  
- *ID del Plugin:* 76474  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Puerto afectado:* udp/161 (SNMP)  
- *Sistema operativo:* Linux Kernel 2.6 (Ubuntu 8.04 Hardy)  

*Impacto:*  
- El servidor responde a peticiones pequeñas con respuestas *desproporcionadamente grandes*.  
- Esto permite amplificar tráfico hacia un tercero, generando un ataque *DDoS reflejado*.  
- Factor de amplificación observado:  
  - *Tamaño petición:* 42 bytes  
  - *Tamaño respuesta:* 2251 bytes  

*Puntuación de Riesgo:*  
- *CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:N/A:P)  
- *CVSS v3.0:* No disponible  
- *VPR:* 4.4  
- *EPSS:* 0.0787 (baja probabilidad de explotación dirigida, pero usado en ataques masivos).  

*Evidencia:*  
Nessus confirmó que el servidor respondió con *2251 bytes* a una petición de apenas *42 bytes*, demostrando el potencial de amplificación.  

*Referencias:*  
- [Nessus Advisory](http://www.nessus.org/u?8b551b5c)  
- CVE-2008-4309  

=== Acciones Recomendadas
1. *Deshabilitar SNMP* si no es requerido para operaciones.  
2. En caso de necesitarlo:  
   - Restringir acceso a *hosts de administración confiables* únicamente.  
   - Cambiar las *community strings* por valores robustos y no predeterminados.  
   - Implementar *ACLs* o *firewalls* para limitar acceso externo.  
3. Habilitar monitoreo de tráfico SNMP para detectar patrones de abuso.  
4. Actualizar la versión de SNMP o considerar migrar a SNMPv3 con autenticación y cifrado.  

*Conclusión:* Aunque no representa un acceso directo al sistema, la exposición de SNMP como vector de *amplificación DDoS* constituye un riesgo de *uso indebido de infraestructura interna para ataques externos*. Su mitigación debe ser prioritaria si el servicio no es esencial.  

== VULN-B040

=== Resumen Ejecutivo
*Problema:* El servicio HTTPS en *tcp/8443* utiliza una versión vulnerable de *OpenSSL* afectada por la falla *ChangeCipherSpec (CCS)* y vulnerabilidades adicionales.  
*Riesgo para el Negocio:* Esta falla permite que un atacante en posición de *Man-in-the-Middle (MiTM)* intercepte y descifre comunicaciones, exponiendo *credenciales, datos confidenciales* y comprometiendo la *confianza de usuarios y clientes*. Además, múltiples fallos asociados permiten *ejecución de código*, *denegación de servicio (DoS)* y *filtración de información*.  
*Urgencia:* Alta. El bug *Heartbleed* tuvo gran notoriedad, y las vulnerabilidades de *CCS* y DTLS son ampliamente conocidas y explotables en entornos de prueba como Metasploitable.  
*Acción:* Actualizar OpenSSL a versiones parcheadas (0.9.8za, 1.0.0m o 1.0.1h según corresponda) y reiniciar el servicio/host.  

=== Análisis Técnico
- *Nombre:* OpenSSL 'ChangeCipherSpec' MiTM Vulnerability  
- *ID del Plugin:* 77200  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Puerto afectado:* tcp/8443 (HTTPS)  
- *Sistema operativo:* Linux Kernel 2.6 (Ubuntu 8.04 Hardy)  

*Impacto principal:*  
- Un atacante puede forzar el uso de *claves derivadas de información pública*, comprometiendo la seguridad de la sesión SSL/TLS.  
- Exposición de datos sensibles (contraseñas, sesiones, tokens).  
- Posibles escenarios de *ejecución remota de código* o *DoS* mediante errores en DTLS y ECDSA.  

*Vulnerabilidades incluidas:*  
- *CVE-2014-0224:* ChangeCipherSpec – MiTM.  
- *CVE-2010-5298:* ssl3_read_bytes, inyección de datos/DoS.  
- *CVE-2014-0076:* ECDSA nonce disclosure (ataque Flush+Reload).  
- *CVE-2014-0195:* Buffer overflow en DTLS fragmentos → RCE/DoS.  
- *CVE-2014-0198:* NULL pointer en do_ssl3_write → DoS.  
- *CVE-2014-0221:* Manejo de handshake en DTLS → DoS.  
- *CVE-2014-3470:* dtls1_get_message_fragment → DoS en ECDH anónimo.  

*Puntuación de Riesgo:*  
- *CVSS v3.0:* 5.6 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L)  
- *CVSS v2.0:* 6.8 (AV:N/AC:M/Au:N/C:P/I:P/A:P)  
- *VPR:* 7.7 (alto)  
- *EPSS:* 0.929 (probabilidad muy alta de explotación).  

*Evidencia:*  
Nessus confirmó que el servidor aceptó un mensaje prematuro de *ChangeCipherSpec*, completando el handshake con *claves derivadas de información pública* → sesión SSL/TLS comprometida.  

*Referencias:*  
- [OpenSSL Advisory – CCS Attack](https://www.openssl.org/news/secadv/20140605.txt)  
- [ImperialViolet CCS Analysis](https://www.imperialviolet.org/2014/06/05/earlyccs.html)  
- [CVE-2014-0224](https://nvd.nist.gov/vuln/detail/CVE-2014-0224)  

=== Acciones Recomendadas
1. *Actualizar OpenSSL*:  
   - Usuarios de OpenSSL 0.9.8 → versión *0.9.8za*.  
   - Usuarios de OpenSSL 1.0.0 → versión *1.0.0m*.  
   - Usuarios de OpenSSL 1.0.1 → versión *1.0.1h*.  
2. *Reiniciar servicios y host* tras aplicar el parche.  
3. Implementar *TLS 1.2 o superior* con suites modernas (AES-GCM).  
4. Monitorear intentos de explotación (IDS/IPS, logs de TLS handshake).  
5. En producción, considerar *rotación de certificados y llaves privadas* si se sospecha explotación previa.  

*Conclusión:* Este conjunto de fallos en OpenSSL representa un *riesgo crítico de intercepción y manipulación de comunicaciones cifradas*. La explotación es pública y trivial en entornos vulnerables, por lo que el *parcheo inmediato y la revisión de claves* es obligatorio.  

== VULN-B041

=== Resumen Ejecutivo
*Problema:* El servidor soporta *SSLv3 con cifrados CBC*, quedando expuesto a la vulnerabilidad *POODLE (Padding Oracle On Downgraded Legacy Encryption)*.  
*Riesgo para el Negocio:* Un atacante en posición de *Man-in-the-Middle (MiTM)* puede descifrar información sensible (cookies, credenciales, tokens) forzando la degradación a SSLv3. Esto compromete la *confidencialidad* y puede derivar en *robo de sesiones* o *escalamiento de privilegios*.  
*Urgencia:* Media-Alta. Aunque SSLv3 es un protocolo obsoleto, si está habilitado en servicios críticos (SMTP, HTTPS, PostgreSQL), representa un riesgo de explotación activa.  
*Acción:* Deshabilitar completamente SSLv3. Si se requiere compatibilidad temporal, habilitar *TLS Fallback SCSV* como mitigación transitoria.  

=== Análisis Técnico
- *Nombre:* SSLv3 POODLE (Padding Oracle On Downgraded Legacy Encryption)  
- *ID del Plugin:* 78479  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Puertos afectados:*  
  - tcp/25 (SMTP)  
  - tcp/443 (HTTPS)  
  - tcp/5432 (PostgreSQL)  
  - tcp/8443 (HTTPS Alt)  
  - tcp/9443 (HTTPS Alt)  
- *Sistema operativo:* Linux Kernel 2.6 (Ubuntu 8.04 Hardy)  

*Impacto principal:*  
- Exposición de datos cifrados → descifrado de cookies, tokens de sesión y credenciales.  
- Permite ataques de *rollback* donde un atacante fuerza al cliente/servidor a usar SSLv3.  
- Compromete la *confidencialidad*, aunque no permite ejecución de código directo.  

*Detalles técnicos:*  
- *Vector de ataque:* MitM en canales soportando SSLv3.  
- *Requisitos:* El cliente y servidor deben aceptar downgrade a SSLv3.  
- *Explotación:* Descifrado byte a byte en ~256 intentos → posible reconstrucción de sesiones.  

*Puntuación de Riesgo:*  
- *CVSS v3.0:* 3.4 (AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)  
- *CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)  
- *VPR:* 5.1 (medio)  
- *EPSS:* 0.9377 (probabilidad muy alta de explotación).  

*Evidencia:*  
Nessus confirmó que el servidor soporta *SSLv3 con CBC* y no implementa *TLS Fallback SCSV*, permitiendo ataques de degradación de protocolo.  

*Referencias:*  
- [POODLE Attack - ImperialViolet](https://www.imperialviolet.org/2014/10/14/poodle.html)  
- [OpenSSL POODLE Advisory](https://www.openssl.org/~bodo/ssl-poodle.pdf)  
- [IETF Draft – TLS Fallback SCSV](https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00)  
- [CVE-2014-3566](https://nvd.nist.gov/vuln/detail/CVE-2014-3566)  

=== Acciones Recomendadas
1. *Deshabilitar SSLv3* en todos los servicios afectados (PostgreSQL, SMTP, HTTPS).  
2. Asegurar el uso de *TLS 1.2 o superior* con cifrados modernos (AES-GCM, ChaCha20-Poly1305).  
3. Si no es posible desactivar SSLv3 de inmediato → habilitar *TLS Fallback SCSV* para prevenir ataques de downgrade.  
4. Monitorear tráfico para identificar intentos de explotación POODLE.  
5. Comunicar a clientes/usuarios la necesidad de actualizar navegadores, clientes de correo y librerías TLS obsoletas.  

*Conclusión:* El soporte a SSLv3 expone la infraestructura a ataques *POODLE*, lo cual compromete la confidencialidad de datos sensibles. Se recomienda *deshabilitar SSLv3 de inmediato* y reforzar la política de cifrado con versiones modernas de TLS.  

== VULN-B042

=== Resumen Ejecutivo
*Problema:* El servidor soporta *cifrados débiles EXPORT_RSA (≤512 bits)*, conocidos como la vulnerabilidad *FREAK*.  
*Riesgo para el Negocio:* Un atacante en posición de *Man-in-the-Middle (MiTM)* puede forzar la negociación de estos cifrados débiles y descifrar comunicaciones sensibles, como credenciales y correos electrónicos. Esto compromete la *confidencialidad* y puede permitir manipulación de datos.  
*Urgencia:* Media. Aunque el ataque requiere condiciones específicas de downgrade, los cifrados EXPORT_RSA están obsoletos y no deben estar habilitados.  
*Acción:* Deshabilitar inmediatamente el soporte para *EXPORT_RSA* y reforzar la política de cifrado para usar *TLS 1.2+ con AES-GCM o ChaCha20-Poly1305*.  

=== Análisis Técnico
- *Nombre:* SSL/TLS EXPORT_RSA ≤512-bit Cipher Suites Supported (FREAK)  
- *ID del Plugin:* 81606  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Puertos afectados:*  
  - tcp/25 (SMTP)  
  - tcp/443 (HTTPS)  
- *Sistema operativo:* Linux Kernel 2.6 (Ubuntu 8.04 Hardy)  

*Impacto principal:*  
- Uso de *RSA de 512 bits* → factorizable en poco tiempo con hardware moderno.  
- Permite descifrado de sesiones TLS forzadas a usar estos cifrados.  
- Afecta la *confidencialidad* e *integridad* de las comunicaciones.  

*Detalles técnicos:*  
- *Vector de ataque:* downgrade de la conexión a EXPORT_RSA mediante MiTM.  
- *Requisitos:* que el cliente y servidor acepten suites EXPORT_RSA.  
- *Explotación:* Descifrado y manipulación de tráfico HTTPS/SMTP en tiempo real.  

*Puntuación de Riesgo:*  
- *CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:N/I:P/A:N)  
- *VPR:* 1.4 (bajo, por antigüedad)  
- *EPSS:* 0.9191 (alta probabilidad de explotación automatizada).  

*Evidencia:*  
Nessus detectó soporte para las siguientes suites débiles en el servidor:  
- EXP-DES-CBC-SHA (RSA 512, DES 40-bit)  
- EXP-RC2-CBC-MD5 (RSA 512, RC2 40-bit)  
- EXP-RC4-MD5 (RSA 512, RC4 40-bit)  

*Referencias:*  
- [SmackTLS - FREAK Attack](https://www.smacktls.com/#freak)  
- [OpenSSL Security Advisory 2015-01-08](https://www.openssl.org/news/secadv/20150108.txt)  
- [CVE-2015-0204](https://nvd.nist.gov/vuln/detail/CVE-2015-0204)  

=== Acciones Recomendadas
1. *Deshabilitar suites EXPORT_RSA* en todos los servicios (SMTP, HTTPS).  
2. Forzar uso de *TLS 1.2 o superior* con cifrados modernos (AES-GCM, ChaCha20).  
3. Validar configuración con herramientas como `openssl s_client` o `testssl.sh`.  
4. Revisar librerías SSL/TLS (OpenSSL, GnuTLS, NSS) y actualizar a versiones seguras.  
5. Implementar auditorías periódicas de configuración SSL/TLS para evitar reaparición de cifrados débiles.  

*Conclusión:* El soporte de *EXPORT_RSA (FREAK)* expone las comunicaciones a ataques de downgrade y descifrado. Se recomienda deshabilitar inmediatamente estas suites y endurecer la configuración TLS en todos los servicios críticos.  

== VULN-B043

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Linux Kernel 2.6 en Ubuntu 8.04 (hardy)* y presenta una vulnerabilidad de *divulgación de información* en los encabezados *ETag* de *Apache Server*.  
*Riesgo para el Negocio:* La exposición de metadatos internos (como números de inodo, tamaños y fechas de modificación de archivos) puede ayudar a atacantes en el reconocimiento del sistema y la preparación de ataques más dirigidos. Si bien no compromete directamente la confidencialidad de datos sensibles, es un *riesgo de exposición innecesaria de información interna*.  
*Urgencia:* *Moderada.* La vulnerabilidad no permite compromiso directo, pero debe mitigarse como parte de una política de reducción de superficie de ataque.  
*Acción:* Configurar Apache para que los encabezados ETag no incluyan números de inodo.  

=== Análisis Técnico
- *Nombre:* Apache Server ETag Header Information Disclosure  
- *ID del Plugin:* 88098  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Información / Exposición  
- *Publicado:* 2003  
- *Modificado:* N/A  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puertos Afectados:*  
  - 192.168.122.187 en el puerto 80/tcp (HTTP)  
  - 192.168.122.187 en el puerto 443/tcp (HTTPS)  
- *Detalles de la Fuga:*  
  - Encabezado *ETag* incluye: número de inodo (838422), tamaño de archivo (588 bytes), fecha de modificación (Nov 2, 2014).  

Esto puede facilitar ataques de fingerprinting y enumeración de recursos internos.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)  
- *VPR Score:* 5.9  
- *EPSS Score:* 0.0032  

=== Acciones Recomendadas
1. *Reconfiguración de Apache:* Deshabilitar inodos en encabezados ETag con la directiva `FileETag`.  
2. *Mitigación Inmediata:* Aplicar ajustes en configuración y reiniciar el servicio web.  
3. *Validación:* Realizar un nuevo escaneo para confirmar que los encabezados no filtran información sensible.  
4. *Política de Seguridad:* Adoptar prácticas de *hardening* en servidores web para minimizar exposición de metadatos.  

*Conclusión:* Aunque no compromete directamente el sistema, esta vulnerabilidad representa una *exposición innecesaria de información interna*. Debe corregirse para reducir la superficie de ataque y mejorar la postura de seguridad general del servidor.

== VULN-B044

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Linux Kernel 2.6 en Ubuntu 8.04 (hardy)* y soporta *SSLv2*, lo que lo hace vulnerable al ataque *DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)*. Esta vulnerabilidad permite a un atacante *desencriptar tráfico TLS capturado* aprovechando debilidades criptográficas en SSLv2.  
*Riesgo para el Negocio:* Un atacante en posición de *man-in-the-middle* puede explotar esta falla para acceder a *comunicaciones cifradas* que deberían ser confidenciales (ej. credenciales de correo electrónico, sesiones web seguras, datos sensibles). Esto implica un *riesgo significativo para la confidencialidad de la información*.  
*Urgencia:* *Alta prioridad de mitigación.* Aunque la explotación requiere un escenario más complejo (ataques de red + tráfico capturado), el hecho de que el servidor siga aceptando SSLv2 expone al negocio a un *riesgo crítico de confidencialidad*.  
*Acción:* Deshabilitar SSLv2 y *cifrados export-grade* en todos los servicios, asegurando que *ningún servicio use la misma clave privada* en servidores que soporten SSLv2.  

=== Análisis Técnico
- *Nombre:* SSL DROWN Attack Vulnerability (CVE-2016-0800)  
- *ID del Plugin:* 89058  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Criptografía / Exposición de Información  
- *Publicado:* 2016  
- *Modificado:* N/A  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puertos Afectados:*  
  - 192.168.122.187 en el puerto 25/tcp (SMTP)  
  - 192.168.122.187 en el puerto 443/tcp (HTTPS)  
  - 192.168.122.187 en el puerto 9443/tcp (HTTPS alternativo)  
- *Detalles Técnicos:* El servidor soporta cifrados débiles, incluyendo:  
  - *EXP-RC2-CBC-MD5* (40-bit, export)  
  - *EXP-RC4-MD5* (40-bit, export)  
  - *RC4-MD5* (128-bit)  

Esto permite ataques de tipo *padding oracle* y recuperación de claves de sesión TLS con esfuerzo computacional moderado.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio (con impacto alto en confidencialidad)  
- *Puntuación Base CVSS v3.0:* 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)  
- *Puntuación Base CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)  
- *VPR Score:* 3.6  
- *EPSS Score:* 0.9015 (alta probabilidad de explotación en la práctica)  

=== Acciones Recomendadas
1. *Deshabilitar SSLv2:* Modificar la configuración de OpenSSL, Apache y cualquier otro servicio que lo soporte.  
2. *Eliminar cifrados export y RC4:* Forzar el uso de suites seguras (TLS 1.2+ con AES-GCM o ChaCha20-Poly1305).  
3. *Rotación de claves privadas:* Garantizar que ninguna clave privada esté siendo utilizada en servidores que aún acepten SSLv2.  
4. *Verificación posterior:* Ejecutar un escaneo posterior a la mitigación para confirmar que SSLv2 ha sido deshabilitado y los cifrados débiles eliminados.  
5. *Política de seguridad:* Implementar controles de ciclo de vida de cifrados para evitar soporte de protocolos obsoletos en futuros despliegues.  

*Conclusión:* La vulnerabilidad *DROWN* compromete la *confidencialidad de las comunicaciones TLS* al aprovechar debilidades de *SSLv2*. Su explotación permite desencriptar datos sensibles y credenciales. Este host debe ser corregido con *urgencia alta* mediante la desactivación de SSLv2 y la eliminación de cifrados débiles.

== VULN-B045

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Linux Kernel 2.6 en Ubuntu 8.04 (hardy)* y su servicio *SSH (puerto 22/tcp)* permite el uso de *algoritmos de cifrado débiles* (Arcfour y variantes).  
*Riesgo para el Negocio:* El uso de cifrados débiles compromete la *confidencialidad* de las conexiones SSH, permitiendo que un atacante con recursos pueda *descifrar tráfico* o aprovechar debilidades en la negociación criptográfica. Esto representa un *riesgo operativo* en la protección de accesos remotos y credenciales administrativas.  
*Urgencia:* *Moderada.* Aunque no es un compromiso inmediato, mantener algoritmos inseguros habilitados *debilita la postura de seguridad* y debe corregirse.  
*Acción:* Reconfigurar el servicio SSH para *deshabilitar Arcfour/arcfour128/arcfour256* y limitarse a algoritmos modernos y seguros (ej. AES-CTR, ChaCha20-Poly1305).  

=== Análisis Técnico
- *Nombre:* SSH Weak Algorithms Supported  
- *ID del Plugin:* 90317  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Criptografía / Debilidad en protocolo  
- *Publicado:* Referencia en RFC 4253 (Sección 6.3)  
- *Modificado:* N/A  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187 en el puerto 22/tcp (SSH)  
- *Algoritmos Débiles Detectados:*  
  - *Servidor → Cliente:* arcfour, arcfour128, arcfour256  
  - *Cliente → Servidor:* arcfour, arcfour128, arcfour256  

Estos algoritmos presentan vulnerabilidades conocidas en la generación de claves y la resistencia criptográfica.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* N/A  
- *Puntuación Base CVSS v2.0:* 4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)  

=== Acciones Recomendadas
1. *Modificar configuración de SSH:* Editar el archivo */etc/ssh/sshd_config* para eliminar Arcfour y forzar algoritmos modernos (ej. `Ciphers aes256-ctr,aes192-ctr,aes128-ctr`).  
2. *Reiniciar servicio:* Reiniciar el demonio SSH para aplicar la nueva configuración.  
3. *Verificación posterior:* Realizar un nuevo escaneo para confirmar que los cifrados débiles ya no están habilitados.  
4. *Política de seguridad:* Implementar controles de ciclo de vida de protocolos para evitar uso de algoritmos inseguros en servicios críticos.  

*Conclusión:* La habilitación de *algoritmos débiles en SSH* compromete la seguridad de accesos administrativos y la confidencialidad de las sesiones. Debe corregirse mediante la reconfiguración del servidor SSH, alineándose con *estándares criptográficos modernos*.

== VULN-B046

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Linux Kernel 2.6 en Ubuntu 8.04 (hardy)* y su servicio *Samba (puerto 445/tcp)* es vulnerable a *Badlock (CVE-2016-2118)*. Esta vulnerabilidad afecta a los protocolos *SAM* y *LSAD* en Samba debido a una negociación inadecuada de niveles de autenticación en canales *RPC*.  
*Riesgo para el Negocio:* Un atacante *man-in-the-middle* puede degradar el nivel de autenticación y ejecutar *llamadas de red Samba arbitrarias* en nombre del usuario interceptado. Esto puede permitir *ver o modificar datos sensibles de Active Directory, deshabilitar servicios críticos o manipular configuraciones de seguridad*.  
*Urgencia:* *Alta.* Aunque la explotación requiere acceso a la comunicación entre cliente y servidor, el impacto potencial sobre *datos sensibles* y *servicios críticos* es severo.  
*Acción:* Actualizar Samba a las versiones seguras (*4.2.11, 4.3.8, 4.4.2 o posteriores*).  

=== Análisis Técnico
- *Nombre:* Samba Badlock Vulnerability  
- *ID del Plugin:* 90509  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.high)  
- *Tipo:* Vulnerabilidad de Autenticación / RPC  
- *Publicado:* Abril 2016  
- *Modificado:* N/A  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187 en el puerto 445/tcp (CIFS/SMB)  
- *Detalles Técnicos:*  
  - Vulnerabilidad en la negociación de autenticación RPC.  
  - Permite ejecución de llamadas Samba en el contexto del usuario interceptado.  
  - Riesgo de acceso y modificación de datos en *Active Directory*.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Alto  
- *Puntuación Base CVSS v3.0:* 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)  
- *Puntuación Base CVSS v2.0:* 6.8 (AV:N/AC:M/Au:N/C:P/I:P/A:P)  
- *VPR Score:* 5.9  
- *EPSS Score:* 0.7865 (probabilidad alta de explotación en la práctica)  

=== Acciones Recomendadas
1. *Actualizar Samba:* Instalar versiones seguras (4.2.11, 4.3.8, 4.4.2 o superiores).  
2. *Segregar servicios críticos:* Minimizar la exposición de SMB/CIFS en redes públicas o no confiables.  
3. *Monitorización:* Revisar registros de Samba en busca de actividad sospechosa y posibles intentos de MITM.  
4. *Política de parches:* Establecer un ciclo regular de actualizaciones de seguridad en servicios de infraestructura crítica.  

*Conclusión:* La vulnerabilidad *Badlock (CVE-2016-2118)* en Samba permite *ejecución remota de llamadas de red en contexto del usuario* a través de ataques MITM, con impacto severo en confidencialidad, integridad y disponibilidad. Se requiere *actualización inmediata* para mitigar el riesgo.

== VULN-B047

=== Resumen Ejecutivo
*Problema:* El host *192.168.122.187* ejecuta *Linux Kernel 2.6 en Ubuntu 8.04 (hardy)* y su servicio *NTP (puerto 123/udp)* responde a *consultas en modo 6*. Estas respuestas pueden ser aprovechadas por atacantes para realizar *ataques de amplificación NTP*.  
*Riesgo para el Negocio:* Un atacante remoto no autenticado puede enviar *consultas especialmente diseñadas* para reflejar y amplificar tráfico hacia un tercero, lo que expone al servidor como *fuente de ataques DDoS*. Aunque no compromete la integridad de los datos del servidor, implica un *riesgo de reputación, disponibilidad y abuso de recursos*.  
*Urgencia:* *Moderada.* Debe mitigarse para evitar que el servidor sea utilizado como parte de una botnet de amplificación.  
*Acción:* Restringir o deshabilitar el soporte de *NTP mode 6 queries* en la configuración del servicio.  

=== Análisis Técnico
- *Nombre:* Network Time Protocol (NTP) Mode 6 Scanner  
- *ID del Plugin:* 97861  
- *Severidad:* #vulnerability_label(VulnerabilityLevel.medium)  
- *Tipo:* Exposición / Riesgo de Amplificación DDoS  
- *Publicado:* N/A  
- *Modificado:* N/A  

*Impacto:*  
- *SO Detectado:* Linux Kernel 2.6 en Ubuntu 8.04 (hardy)  
- *Host y Puerto Afectado:* 192.168.122.187 en el puerto 123/udp (NTP)  
- *Detalles Técnicos:*  
  - El servidor responde a consultas *mode 6*.  
  - Ejemplo de respuesta: versión de *ntpd 4.2.4p4* (2008), información de sistema, parámetros de reloj y sincronización.  
  - Esta información puede ser abusada en ataques de reflexión/amplificación.  

*Puntuación de Riesgo:*  
- *Factor de Riesgo:* Medio  
- *Puntuación Base CVSS v3.0:* 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L)  
- *Puntuación Base CVSS v2.0:* 5.0 (AV:N/AC:L/Au:N/C:N/I:N/A:P)  

=== Acciones Recomendadas
1. *Restringir consultas mode 6:* Configurar *ntpd* para aceptar únicamente consultas administrativas desde direcciones autorizadas.  
2. *Actualizar NTP:* Usar versiones más recientes con mitigaciones por defecto frente a ataques de amplificación.  
3. *Monitoreo de tráfico:* Revisar registros y tráfico de red para detectar intentos de explotación.  
4. *Buenas prácticas:* Evitar exponer NTP directamente a Internet salvo que sea estrictamente necesario.  

*Conclusión:* El servicio NTP en el host analizado responde a *consultas en modo 6*, lo que lo expone a ser usado en *ataques de amplificación DDoS*. Se recomienda aplicar restricciones en la configuración y mantener actualizado el servicio para mitigar el riesgo.



= Vulnerabilidades Bajas

// ==================== ANÁLISIS DE RIESGO ====================
= Análisis de Riesgo

== Matriz de Riesgo

#table(
  columns: (1fr, auto, auto, auto, auto),
  stroke: 0.5pt + gray,
  fill: (x, y) => {
    if y == 0 { rgb("#1f4788").lighten(90%) }
    else if x > 0 and y > 0 {
      let risk_colors = (
        rgb("#ff4757").lighten(80%), // Crítico
        rgb("#ff6b35").lighten(80%), // Alto  
        rgb("#f39c12").lighten(80%), // Medio
        rgb("#26de81").lighten(80%)  // Bajo
      )
      risk_colors.at(calc.min(x - 1, 3))
    }
  },
  
  table.header(
    [*Categoría*], [*Crítico*], [*Alto*], [*Medio*], [*Bajo*]
  ),
  [Sistema Operativo], [X], [X], [X], [X],
  [Servicios de Red], [X], [X], [X], [X],
  [Configuración], [X], [X], [X], [X],
  [Aplicaciones], [X], [X], [X], [X]
)

== Impacto Potencial

*Riesgo Financiero:* Estimado entre \$XXX,XXX y \$X,XXX,XXX en caso de explotación exitosa.

*Riesgo Operacional:* Posible interrupción de servicios críticos durante 24-72 horas.

*Riesgo Reputacional:* Potencial pérdida de confianza de clientes y socios comerciales.

*Riesgo Regulatorio:* Posibles sanciones por incumplimiento de normativas de protección de datos.

// ==================== RECOMENDACIONES ====================
= Plan de Remediación

== Acciones Inmediatas (0-7 días)

#alert_box(
  title: "Crítico - Acción Inmediata",
  content: [
    1. *Aplicar parches críticos* en sistemas identificados como VULN-001, VULN-002
    2. *Deshabilitar servicios innecesarios* en máquinas virtuales críticas
    3. *Implementar reglas de firewall* restrictivas temporales
    4. *Activar logging adicional* en sistemas críticos
  ]
)

== Acciones a Corto Plazo (1-4 semanas)

1. *Actualización completa* de sistemas operativos en todas las VM
2. *Configuración de hardening* según mejores prácticas (CIS Benchmarks)
3. *Implementación de autenticación* de doble factor donde sea posible
4. *Establecimiento de políticas* de gestión de parches

== Acciones a Mediano Plazo (1-3 meses)

1. *Implementación de SIEM* para monitoreo continuo
2. *Desarrollo de procedimientos* de respuesta a incidentes
3. *Capacitación del equipo* técnico en seguridad
4. *Auditorías regulares* de configuración

== Acciones a Largo Plazo (3-12 meses)

1. *Migración a arquitectura* de seguridad zero-trust
2. *Implementación de automatización* para gestión de parches
3. *Desarrollo de métricas* de seguridad (KPIs)
4. *Establecimiento de programa* de bug bounty interno

// ==================== CONCLUSIONES ====================
= Conclusiones y Próximos Pasos

== Resumen de Hallazgos

La evaluación reveló [NÚMERO] vulnerabilidades distribuidas en múltiples niveles de criticidad. Si bien la mayoría de las vulnerabilidades identificadas pueden ser remediadas mediante la aplicación de parches y mejores prácticas de configuración, es crucial abordar las vulnerabilidades críticas dentro de las próximas 48-72 horas.

== Recomendaciones Ejecutivas

1. *Asignación inmediata de recursos* para la remediación de vulnerabilidades críticas
2. *Establecimiento de un cronograma* claro para la implementación de mejoras
3. *Designación de un equipo* responsable del seguimiento y cumplimiento
4. *Programación de evaluaciones* regulares de seguridad (trimestrales)

== Próximos Pasos

1. *Aprobación del plan* de remediación por parte de la dirección
2. *Asignación de presupuesto* y recursos necesarios
3. *Comunicación del plan* a todos los stakeholders relevantes
4. *Inicio de implementación* de acciones inmediatas

// ==================== APÉNDICES ====================
= Apéndices

== Apéndice A: Lista Completa de Vulnerabilidades

[Incluir tabla detallada con todas las vulnerabilidades encontradas]

== Apéndice B: Evidencia Técnica

[Incluir capturas de pantalla, logs relevantes, outputs de herramientas]

== Apéndice C: Referencias y Estándares

- NIST Cybersecurity Framework
- CIS Controls v8
- OWASP Top 10
- CVE Database
- CVSS v3.1 Specification

== Apéndice D: Glosario de Términos

*CVE:* Common Vulnerabilities and Exposures

*CVSS:* Common Vulnerability Scoring System

*SIEM:* Security Information and Event Management

*VM:* Virtual Machine

[Agregar términos adicionales según sea necesario]