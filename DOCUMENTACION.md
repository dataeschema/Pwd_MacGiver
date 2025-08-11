# Pwd MacGiver - Documentación

## 1. Descripción General

**Pwd MacGiver** es una aplicación de escritorio segura para gestionar credenciales de servicios. A diferencia de un simple generador de contraseñas, actúa como una bóveda o almacén digital donde el usuario puede guardar, modificar y consultar información sensible como nombres de usuario, contraseñas, servidores y bases de datos.

La aplicación está protegida por una **contraseña maestra**, que se utiliza para cifrar toda la información almacenada, garantizando que solo el usuario con acceso a dicha contraseña pueda ver los datos.

## 2. Características Principales

- **Bóveda Segura:** Almacena todas las credenciales en un único archivo de base de datos (`vault.db`).
- **Cifrado Fuerte:** Utiliza criptografía robusta para proteger los datos.
  - La clave de cifrado se deriva de la contraseña maestra usando **PBKDF2** con 200,000 iteraciones y SHA-256.
  - Los datos sensibles se cifran usando el algoritmo simétrico **Fernet** (AES de 128 bits en modo CBC).
- **Contraseña Maestra:** En el primer uso, la aplicación solicita la creación de una contraseña maestra. En usos posteriores, es imprescindible para acceder.
- **Interfaz Gráfica Moderna:** Desarrollada con **PySide6 (Qt)**, con un diseño oscuro y funcional.
- **Gestión de Credenciales (CRUD):**
  - **Añadir:** Permite agregar nuevas credenciales de servicios.
  - **Modificar:** Permite editar un servicio existente.
  - **Eliminar:** Permite borrar un servicio de forma segura.
- **Funcionalidades Útiles:**
  - **Buscador integrado:** Filtra los servicios en tiempo real.
  - **Copiado al portapapeles:** Haciendo doble clic en cualquier celda, su contenido se copia al portapapeles.
  - **Notificaciones visuales:** Un banner temporal confirma que un dato ha sido copiado.
- **Configuración Personalizable:** Permite ajustar y guardar el tamaño inicial de la ventana.

## 3. Tecnologías Utilizadas

- **Lenguaje:** Python 3
- **Interfaz Gráfica:** PySide6 (bindings oficiales de Qt para Python)
- **Base de Datos:** SQLite 3
- **Criptografía:** `cryptography` (una de las bibliotecas criptográficas más reconocidas de Python).

## 4. Funcionamiento Detallado

### Arranque y Autenticación

1.  **Primer Arranque:** Si no existe una base de datos o no se ha configurado una contraseña maestra, la aplicación mostrará un diálogo para crear una. Se genera una "sal" criptográfica (`salt`) que se guarda en la base de datos. Esta "sal" se usará junto a la contraseña para derivar la clave de cifrado.
2.  **Arranques Posteriores:** La aplicación solicitará la contraseña maestra. El sistema la utiliza, junto con la "sal" almacenada, para derivar una clave. Si la clave resultante es correcta (verificándola contra un hash guardado), se desbloquea la bóveda. Si no, se deniega el acceso.

### Estructura de la Base de Datos (`vault.db`)

La base de datos SQLite contiene tres tablas principales:
- `meta`: Almacena metadatos críticos como la "sal" criptográfica y el hash verificador de la clave.
- `config`: Guarda configuraciones de la aplicación, como el tamaño de la ventana.
- `services`: Almacena las credenciales. Campos como `username`, `password`, `server` y `database` se guardan en formato `BLOB` (binario) porque contienen los datos cifrados.

### Interfaz Principal

La ventana principal consta de:
- Una **barra de herramientas superior** con un campo de búsqueda y los botones de acción (Añadir, Modificar, Eliminar, Configuración).
- Una **tabla central** que lista todos los servicios. Las contraseñas se muestran ofuscadas con puntos (`•••••`) por seguridad.
- Un **pie de página** que muestra el número total de servicios almacenados.

## 5. Dependencias

Para ejecutar la aplicación desde el código fuente, necesitas instalar las siguientes bibliotecas de Python:

```bash
pip install PySide6 cryptography
```

## 6. Cómo Usar la Aplicación

1.  **Ejecutar el script:** `python Pwd_MacGiver.py`.
2.  **Crear/Introducir Contraseña Maestra:** Sigue las instrucciones del diálogo inicial.
3.  **Añadir un Servicio:**
    - Haz clic en el botón "Añadir".
    - Rellena los campos en el nuevo diálogo y haz clic en "Ok".
4.  **Copiar un dato:**
    - Haz doble clic en la celda deseada (ej: la contraseña del servicio "Gmail").
    - El dato se copiará al portapapeles y un banner verde lo confirmará.
5.  **Buscar un Servicio:**
    - Escribe en la barra de búsqueda. La tabla se filtrará automáticamente.
6.  **Modificar o Eliminar:**
    - Selecciona la fila del servicio que deseas cambiar.
    - Haz clic en "Modificar" o "Eliminar".

## 7. Utilidades de Desarrollo

El fichero `tools.txt` contiene comandos útiles para el desarrollo y empaquetado de la aplicación.

### 1. Generar `icon.txt` a partir de `icon.png`

Para actualizar el icono de la aplicación que se embebe en el código, primero debes tener tu icono en formato `PNG` (`icon.png`). Luego, ejecuta el siguiente comando para convertirlo a formato base64 y guardarlo en `icon.txt`. La aplicación leerá este fichero para mostrar el icono.

```bash
python -c "import base64; open('icon.txt','w').write(base64.b64encode(open('icon.png','rb').read()).decode())"
```

### 2. Empaquetar la aplicación con PyInstaller para Windows

Para crear un ejecutable autocontenido (`.exe`) para Windows, puedes usar `PyInstaller`. El siguiente comando compila el script de Python en un único fichero, sin ventana de consola y con el icono `app.ico`.

```bash
pyinstaller Pwd_MacGiver.py --name Pwd_MacGiver --onefile --noconsole --icon .\app.ico
```

## 8. Empaquetado para macOS (Apple Silicon)

Es posible generar un ejecutable autocontenido (`.app`) para macOS con Apple Silicon (M1/M2/etc.).

### Requisitos

1.  **Entorno de Compilación:** El proceso debe ejecutarse en un Mac con Apple Silicon.
2.  **Python Nativo:** La versión de Python debe ser nativa para la arquitectura `arm64`.
3.  **Dependencias:** Instalar las mismas dependencias en el Mac:
    ```bash
    pip install PySide6 cryptography pyinstaller
    ```
4.  **Formato de Icono:** macOS utiliza el formato `.icns`.

### Pasos para Generar el Ejecutable

#### 1. Crear el Fichero de Icono (`.icns`)

Para convertir un `icon.png` a `.icns`, puedes usar la utilidad `iconutil` de macOS:

1.  Crea un directorio para el set de iconos:
    ```bash
    mkdir mi_icono.iconset
    ```
2.  Genera las diferentes resoluciones de tu `icon.png` y guárdalas en el directorio:
    ```bash
    sips -z 16 16 icon.png --out mi_icono.iconset/icon_16x16.png
    sips -z 32 32 icon.png --out mi_icono.iconset/icon_32x32.png
    sips -z 128 128 icon.png --out mi_icono.iconset/icon_128x128.png
    sips -z 256 256 icon.png --out mi_icono.iconset/icon_256x256.png
    ```
3.  Convierte el directorio `.iconset` en un fichero `.icns`:
    ```bash
    iconutil -c icns mi_icono.iconset
    ```
    Esto generará el fichero `mi_icono.icns`.

#### 2. Generar la Aplicación (`.app`)

Usa `PyInstaller` con el siguiente comando para generar el paquete de aplicación:

```bash
pyinstaller Pwd_MacGiver.py --name Pwd_MacGiver --windowed --icon mi_icono.icns
```

- `--windowed`: Crea una aplicación de GUI sin una ventana de terminal (equivalente a `--noconsole` en Windows).
- `--icon mi_icono.icns`: Asigna el icono en formato `.icns`.

El resultado será `Pwd_MacGiver.app` en la carpeta `dist`, listo para distribuir.
