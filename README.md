# Bastionado y Mitigación de Vulnerabilidades en OWASP WebGoat

[![Java](https://img.shields.io/badge/Java-25-orange.svg)](https://jdk.java.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1.2-green.svg)](https://spring.io/projects/spring-boot)
[![Security Standards](https://img.shields.io/badge/OWASP-Top%2010%20%7C%20CWE-blue.svg)](https://owasp.org/Top10/)
[![Security Tests](https://img.shields.io/badge/Security%20Tests-4%20Suites%20(28%20cases)-blue.svg)](#validación-y-pruebas)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org)

Este repositorio contiene la implementación técnica de bastionado de seguridad (*Security Hardening*) sobre la infraestructura de **OWASP WebGoat**, desarrollada como proyecto final para la asignatura de **Hacking Ético**.

El objetivo central consistió en diseñar, implementar, probar y documentar la mitigación de cuatro vulnerabilidades críticas descubiertas durante la auditoría inicial de seguridad del aplicativo, concentrando las correcciones en la infraestructura del contenedor (`org.owasp.webgoat.container`) y preservando la integridad didáctica de las lecciones deliberadamente vulnerables. Fuera del contenedor solo se modificó cómo cuatro lecciones entregan su correo y el enlace a la hoja de estilos de tres lecciones; ninguna de sus vulnerabilidades didácticas cambió.

---

## Matriz Resumen de Vulnerabilidades Mitigadas

| ID | Vulnerabilidad | Clasificación CWE / OWASP | Componentes / Archivos Afectados | Técnica Defensiva Implementada |
| :--- | :--- | :--- | :--- | :--- |
| **V1** | **Autorización Faltante en `/WebGoat/service/debug/labels.mvc`** | **CWE-862**<br>OWASP A01:2021 | `WebSecurityConfig.java`<br>`LabelDebugService.java` | Restricción de `/service/debug/**` al rol `WEBGOAT_ADMIN` en Spring Security (`SecurityFilterChain`) y defensa en profundidad con `@PreAuthorize("hasAuthority('WEBGOAT_ADMIN')")` sobre `LabelDebugService`. El cambio de estado solo se acepta por `POST`. |
| **V2** | **Transmisión en Texto Plano y Cookies Inseguras** | **CWE-319**<br>OWASP A02:2021 | `application-webgoat.properties`<br>`goatkeystore.pkcs12`<br>`WebSecurityConfig.java` | Forzado de cifrado en tránsito TLSv1.2/1.3 con suites AEAD GCM en Tomcat, rechazo de texto plano y atributos `Secure`, `HttpOnly` y `SameSite=Lax` en `JSESSIONID`. |
| **V3** | **Ausencia de Cabeceras Defensivas HTTP** | **CWE-693**<br>OWASP A05:2021 | `WebSecurityConfig.java` | Reconfiguración de Spring Security inyectando `HSTS` (31536000 s), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP` y `Referrer-Policy`. |
| **V4** | **Fuga de Información Sensible en Errores** | **CWE-209**<br>OWASP A05:2021 | `GlobalExceptionHandler.java`<br>`application-webgoat.properties`<br>`error.html` | Supresión de stack traces en configuración (`spring.web.error.include-stacktrace=never`) y `@ControllerAdvice` que desvía diagnósticos a logs internos y responde con JSON/HTML limpios conservando el código de estado original. |

---

## Detalle Técnico de las Soluciones

### V1 — Control de Acceso Basado en Roles en Servicio Global de Depuración (CWE-862)
* **Causa Raíz:** En `WebSecurityConfig.java`, la autoridad `WEBGOAT_ADMIN` restringía únicamente `/service/admin/**`, dejando `/WebGoat/service/debug/labels.mvc` bajo `.anyRequest().authenticated()`. Además, `LabelDebugService.java` carecía de `@PreAuthorize` y permitía consultar o modificar el bean singleton compartido `LabelDebugger` mediante peticiones `GET` desde cualquier cuenta estándar.
* **Solución Implementada:**
  1. Se restringió `/service/debug/**` en `WebSecurityConfig.java` exigiendo `.hasAuthority("WEBGOAT_ADMIN")`.
  2. Se reforzó `LabelDebugService.java` con `@PreAuthorize("hasAuthority('WEBGOAT_ADMIN')")` aprovechando `@EnableMethodSecurity`.
  3. Toda solicitud anónima (`302` hacia `/login`) o autenticada sin privilegios (`HTTP 403 Forbidden` en JSON) queda rechazada sin alterar `LabelDebugger`, manteniendo operativos el acceso `WEBGOAT_ADMIN` y el endpoint público `/service/labels.mvc`.
  4. El cambio de estado de `LabelDebugger` solo se acepta por `POST`; un `GET` con `?enabled=` únicamente consulta el estado. Así, un enlace externo abierto por un administrador no puede modificarlo (las cookies `SameSite=Lax` sí viajan en navegaciones `GET` entre sitios).
  5. Se implementó la suite `LabelDebugAccessControlTest.java` (10 casos cubriendo filtro HTTP, seguridad por método, acceso administrativo, `GET` de solo lectura y `/service/labels.mvc`).

### V2 — Cifrado en Tránsito y Endurecimiento de Sesión (CWE-319)
* **Causa Raíz:** WebGoat iniciaba por defecto en HTTP sin cifrar sobre el puerto 8080 y emitía la cookie `JSESSIONID` sin flags de protección.
* **Solución Implementada:**
  1. Se habilitó el conector SSL en `application-webgoat.properties` (`server.ssl.enabled=true`) vinculado al almacén de claves PKCS12 `goatkeystore.pkcs12`.
  2. Se restringieron los protocolos exclusivamente a `TLSv1.2` y `TLSv1.3` con suites AEAD GCM: `TLS_AES_128_GCM_SHA256` y `TLS_AES_256_GCM_SHA384` para TLS 1.3, y `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` y `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` para TLS 1.2. Sin las suites de TLS 1.3 en la lista, ese protocolo no llega a negociarse.
  3. Se endureció la cookie de sesión mediante las directivas:
     ```properties
     server.servlet.session.cookie.secure=true
     server.servlet.session.cookie.http-only=true
     server.servlet.session.cookie.same-site=lax
     ```
  4. Las solicitudes HTTP no cifradas son rechazadas inmediatamente a nivel de socket con `HTTP 400 Bad Request`.
  5. Las lecciones que enviaban correo con una llamada HTTP interna a `/WebGoat/mail` (que dejó de funcionar al exigir TLS) ahora lo entregan dentro del proceso mediante `MailboxService`.
  6. El `HEALTHCHECK` del `Dockerfile` consulta `https://` y la imagen instala `curl`, que la imagen base no incluye.

### V3 — Inyección de Cabeceras Defensivas HTTP (CWE-693)
* **Causa Raíz:** La clase de seguridad `WebSecurityConfig.java` contenía la directiva `headers.disable()`, anulando todas las defensas del navegador.
* **Solución Implementada:** Se reestructuró la cadena de filtros de Spring Security 7 activando el DSL de cabeceras defensivas:
  - `Strict-Transport-Security: max-age=31536000 ; includeSubDomains` (HSTS durante 1 año).
  - `X-Frame-Options: DENY` (Mitigación total contra Clickjacking / UI Redressing).
  - `X-Content-Type-Options: nosniff` (Protección estricta contra ataques de MIME Sniffing).
  - `Referrer-Policy: strict-origin-when-cross-origin` (Prevención de fuga de rutas sensibles).
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://code.jquery.com; img-src 'self' data: https://code.jquery.com; font-src 'self' data:; connect-src 'self'` (Defensa en profundidad contra XSS e inyecciones no confiables). Se permite `https://code.jquery.com` solo para la hoja de estilos jQuery UI que usan tres lecciones, cuyo enlace pasó de `http://` a `https://`.
  - WebWolf (puerto 9090) queda fuera del alcance de estas cabeceras.

### V4 — Supresión de Stack Traces y Manejo de Errores Desacoplado (CWE-209)
* **Causa Raíz:** `application-webgoat.properties` forzaba `include-stacktrace=always`, exponiendo volcados de clases de Java y Spring ante cualquier error 404 o 500.
* **Solución Implementada:**
  1. Se eliminó la directiva vulnerable y se configuró la supresión radical en propiedades:
     ```properties
     spring.web.error.include-stacktrace=never
     spring.web.error.include-message=never
     spring.web.error.include-binding-errors=never
     spring.web.error.include-exception=false
     spring.web.error.whitelabel.enabled=false
     ```
     Spring Boot 4 movió estas propiedades de `server.error.*` a `spring.web.error.*` e ignora los nombres antiguos.
  2. Se creó el controlador `GlobalExceptionHandler` anotado con `@ControllerAdvice`.
  3. Desacoplamiento de responsabilidades: los diagnósticos técnicos completos se registran exclusivamente en los archivos de log del servidor con `log.error()`, mientras que al cliente se le entrega una respuesta sanitizada.
  4. Soporte híbrido: detecta si la petición proviene de una API (`Accept: application/json`) para devolver un JSON limpio o de un navegador (`Accept: text/html`) devolviendo la plantilla `error.html` diseñada con estilos limpios sin volcados JVM.
  5. Cada error conserva su código de estado original (`400`, `404`, `405` con su cabecera `Allow`, `406`, `415`); solo los fallos inesperados responden `500`. Las excepciones de Spring Security se relanzan para que la cadena de filtros responda `403` o redirija al login.
  6. Algunas lecciones muestran trazas a propósito como parte de su ejercicio (por ejemplo, XXE) y se dejaron sin cambios.

---

## Estrategia de Ramas en Git y Trazabilidad

Se implementó una estrategia **Git Flow** con ramas aisladas para mantener la separación de responsabilidades y permitir la revisión independiente de cada solución:

```mermaid
gitGraph
   commit id: "Initial-Code"
   branch fix/v1-access-control
   checkout fix/v1-access-control
   commit id: "fa57a68 (V1-AccessControl)"
   checkout main
   branch fix/v2-tls
   checkout fix/v2-tls
   commit id: "a2b8a62 (V2-TLS)"
   commit id: "f8f9c02 (V2-Fix)"
   checkout main
   branch fix/v3-security-headers
   checkout fix/v3-security-headers
   commit id: "d5cf60d (V3-Headers)"
   checkout main
   branch fix/v4-error-handling
   checkout fix/v4-error-handling
   commit id: "fd55156 (V4-Errors)"
   commit id: "85b16fe (V4-Fix)"
   checkout main
   branch test/all-fixes
   checkout test/all-fixes
   merge fix/v1-access-control
   merge fix/v2-tls
   merge fix/v3-security-headers
   merge fix/v4-error-handling
   checkout main
   merge test/all-fixes
   checkout test/all-fixes
   commit id: "9975693 (V2-TLS13-Healthcheck)"
   commit id: "1cb1196 (Lessons-Mail)"
   commit id: "f5cf168 (V4-Status-Codes)"
   commit id: "a2a058f (V1-POST-only)"
   commit id: "cff4bbb (V3-CSP-jQueryUI)"
```

### Tabla de Commits de Seguridad

| Hash | Rama | Tipo | Mensaje de Commit | Autor |
| :--- | :--- | :--- | :--- | :--- |
| `fa57a68` | `fix/v1-access-control` | `fix(security)` | restrict /service/debug/** to WEBGOAT_ADMIN (V1) | Diego Castro |
| `a2b8a62` | `fix/v2-tls` | `feat(security)` | enforce TLS encryption and secure cookie flags for WebGoat transport (V2) | Diego Castro |
| `f8f9c02` | `fix/v2-tls` | `fix(security)` | rely on native container SSL and avoid deprecated channel filter | Diego Castro |
| `d5cf60d` | `fix/v3-security-headers` | `fix(security)` | enable defensive HTTP headers (CSP, HSTS, XFO, nosniff) in WebSecurityConfig (V3) | Diego Castro |
| `fd55156` | `fix/v4-error-handling` | `fix(security)` | suppress stack trace leakage and implement GlobalExceptionHandler (V4) | Diego Castro |
| `85b16fe` | `fix/v4-error-handling` | `style(security)`| apply spotless formatting and fix test signatures | Diego Castro |
| `9975693` | `test/all-fixes` | `fix(security)` | negotiate TLS 1.3 and fix the Docker healthcheck (V2) | Cristian Barrera |
| `1cb1196` | `test/all-fixes` | `fix(lessons)` | deliver lesson e-mail in-process instead of an HTTP self-call | Cristian Barrera |
| `f5cf168` | `test/all-fixes` | `fix(security)` | keep client error status codes and serve the error page (V4) | Cristian Barrera |
| `a2a058f` | `test/all-fixes` | `fix(security)` | make label debugging state changes POST-only (V1) | Cristian Barrera |
| `cff4bbb` | `test/all-fixes` | `fix(security)` | load the lesson jquery-ui stylesheet over HTTPS under CSP (V3) | Cristian Barrera |

Los cinco últimos commits corrigen los problemas que una auditoría independiente encontró sobre la primera integración: TLS 1.3 no se negociaba, las lecciones de correo fallaban, el healthcheck de Docker no funcionaba, varios errores del cliente respondían `500` y la página Whitelabel seguía apareciendo.

---

## Guía de Despliegue y Ejecución

> [!NOTE]
> WebGoat utiliza **Java 25**. Para asegurar reproducibilidad inmediata en cualquier estación de trabajo sin requerir la instalación manual de JDK 25 en el sistema operativo anfitrión, el entorno se compila y ejecuta mediante el contenedor oficial **Eclipse Temurin 25**.

### 1. Clonar el repositorio y posicionarse en la rama unificada
```bash
git clone https://github.com/dacastro125/Some-WebGoat-Security-Fixes.git
cd Some-WebGoat-Security-Fixes
git checkout test/all-fixes
```

### 2. Compilar el artefacto (.jar)
```bash
docker run --rm -v "${PWD}:/app" -v "${HOME}/.m2:/root/.m2" -w /app eclipse-temurin:25-jdk-noble ./mvnw clean package -DskipTests
```

### 3. Iniciar el servidor WebGoat
Mapeamos el puerto HTTPS al **`8443`** para evitar colisiones con el puerto por defecto de Burp Suite (`8080`):

```bash
docker run --name webgoat-live --rm -d \
  -p 8443:8080 -p 9090:9090 \
  -v "${PWD}/target:/home/webgoat" -w /home/webgoat \
  eclipse-temurin:25-jdk-noble java \
  "-Duser.home=/home/webgoat" "-Dfile.encoding=UTF-8" \
  --add-opens java.base/java.lang=ALL-UNNAMED \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
  --add-opens java.base/java.text=ALL-UNNAMED \
  --add-opens java.desktop/java.beans=ALL-UNNAMED \
  --add-opens java.desktop/java.awt.font=ALL-UNNAMED \
  --add-opens java.base/sun.nio.ch=ALL-UNNAMED \
  --add-opens java.base/java.io=ALL-UNNAMED \
  "-Drunning.in.docker=true" \
  -jar webgoat-2026.6-SNAPSHOT.jar --server.address=0.0.0.0
```

### 4. Acceso y Credenciales
- **URL WebGoat:** [https://localhost:8443/WebGoat](https://localhost:8443/WebGoat) *(aceptar la advertencia del certificado autofirmado local)*.
- **URL WebWolf:** [http://localhost:9090/WebWolf](http://localhost:9090/WebWolf)
- **Credenciales del Sistema:**
  - **Usuario Estándar:** `webgoat-user` | Contraseña: `webgoat`
  - **Usuario Administrador:** `webgoat-admin` | Contraseña: `webgoat`

### 5. Detener el servidor
```bash
docker stop webgoat-live
```

---

## Validación y Pruebas

### 1. Pruebas Unitarias y de Integración Automatizadas
Se desarrollaron 4 suites específicas para las vulnerabilidades mitigadas (**28 casos en total**), ejecutables con Maven Surefire:

```bash
docker run --rm -v "${PWD}:/app" -v "${HOME}/.m2:/root/.m2" -w /app eclipse-temurin:25-jdk-noble ./mvnw test "-Dtest=LabelDebugAccessControlTest,TransportSecurityTest,SecurityHeadersTest,GlobalExceptionHandlerTest"
```

- `LabelDebugAccessControlTest` (**10** casos), `TransportSecurityTest` (**3** casos), `SecurityHeadersTest` (**5** casos) y `GlobalExceptionHandlerTest` (**10** casos).
- La suite completa del proyecto (`./mvnw test`) pasa con **426** pruebas, 0 fallos y 1 omitida.

### 2. Verificación Dinámica en Vivo con Burp Suite
* **V1 (Control de Acceso - CWE-862):** Al enviar `GET /WebGoat/service/debug/labels.mvc?enabled=true` con una sesión estándar (`usuarioprueba1` / `webgoat-user`), el servidor responde `HTTP/1.1 403` en JSON (`"error":"Forbidden"`) sin modificar `LabelDebugger`; un `POST` desde esa sesión también recibe `403`. Con `webgoat-admin`, el `GET` responde `200 OK` pero no cambia el estado, y solo un `POST` con `enabled=true` lo modifica. `/WebGoat/service/labels.mvc` responde `200 OK`.
* **V2 (TLS & Cookie):** Al iniciar sesión (`POST /WebGoat/login`), la respuesta emite `Set-Cookie: JSESSIONID=...; Path=/WebGoat; Secure; HttpOnly; SameSite=Lax`. Las peticiones en texto plano por puerto HTTP son rechazadas con `HTTP 400`. Con `openssl s_client` se negocian `TLSv1.3` y `TLSv1.2`, y `TLSv1.1` se rechaza.
* **V3 (Cabeceras):** Se corroboró la inyección en todas las respuestas de `HSTS`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y `CSP`.
* **V4 (Manejo de Errores):** Al enviar peticiones a rutas inexistentes (`GET /WebGoat/recurso_inexistente_auditoria`), el servidor devuelve `HTTP/1.1 404 Not Found` en JSON y HTML completamente limpios, con **cero volcados de stack traces de la JVM**; en HTML se muestra la página de error de WebGoat en lugar de la Whitelabel. Un `POST` a una ruta que solo admite `GET` (por ejemplo `/WebGoat/proxy.pac`) responde `405` con `Allow: GET`, y un cuerpo JSON malformado responde `400`.

---

## Equipo de Trabajo y Aportes

| Integrante | Área / Vulnerabilidad Liderada |
| :--- | :--- |
| **Danilo** | **V1:** Control de Acceso Basado en Roles (`WEBGOAT_ADMIN`) en `/service/debug/labels.mvc` (CWE-862) sobre `WebSecurityConfig` y `LabelDebugService`. |
| **Diego Castro** | **V2:** Cifrado de Transporte TLS y Endurecimiento de Cookies de Sesión (CWE-319) e integración general. |
| **Cristian** | **V3:** Inyección de Cabeceras Defensivas HTTP y Seguridad del Protocolo (CWE-693). Segunda ronda de correcciones V1–V4 tras la auditoría independiente (commits `9975693` a `cff4bbb`). |
| **Bonilla** | **V4:** Supresión de Fuga de Información en Errores y Controlador Global (CWE-209). |

---

> [!IMPORTANT]
> **Aviso de Responsabilidad Ética:** Este proyecto fue desarrollado con propósitos académicos y de investigación en seguridad informática. El análisis y las pruebas de penetración se realizaron de manera controlada y autorizada en entornos locales aislados.
