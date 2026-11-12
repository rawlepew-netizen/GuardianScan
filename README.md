# GuardianScan
1. Abre esta carpeta en Android Studio (Koala o superior) y deja que sincronice Gradle.
2. Conecta tu teléfono (depuración USB) y pulsa Run.
3. Botón 2: concede "Acceso a uso". Botón 3: acepta el diálogo de VPN.
Limitaciones: no detecta Pegasus (zero-click, sin rastro en apps). Ve solo DNS, no contenido.
Apps con DNS-over-HTTPS propio o IP fija no pasan por el monitor. Desactiva "DNS privado" en Ajustes para que capture todo.

## IOC (como MVT)
Descarga los indicadores STIX2 (archivos .stix2/.json) desde github.com/AmnestyTech/investigations
y github.com/mvt-project/mvt-indicators, cópialos al teléfono y usa "Importar IOC".
