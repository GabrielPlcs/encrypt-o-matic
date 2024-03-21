Aquí un posible README.md para documentar el código de cifrado de archivos en GitHub:

# Cifrado de archivos symétrico

Este proyecto implementa el cifrado y descifrado de archivos y directorios de forma recursiva usando cifrado simétrico AES en modo EAX.

## Funcionalidad

- Cifra y descifra archivos de manera individual.

- Cifra y descifra directorios de forma recursiva, incluyendo todos los archivos y subdirectorios. 

- Genera claves AES aleatorias de longitud configurable y las guarda en archivos.

- Usa el módulo cryptography de Python para cifrado robusto.

- Interfaz sencilla por línea de comandos.

## Uso

### Requisitos

- Python 3
- Librería cryptography

### Ejecución

```
python xor.py 
```

Se mostrará un menú con opciones para:

- Cifrar archivo
- Descifrar archivo 
- Generar clave
- Salir

### Parámetros

- Ruta y nombre de archivos/directorios de entrada y salida
- Ruta y nombre del archivo con la clave
- Longitud de claves generadas

## Documentación

Algoritmos y modos de operación
El cifrado se realiza usando AES en modo EAX (Authenticated Encryption with Additional Data).

AES es un algoritmo de cifrado por bloques simétrico robusto. El modo EAX ofrece cifrado autenticado, proporcionando tanto confidencialidad como integridad de los datos.

Generación y almacenamiento de claves
Las claves AES se generan de forma aleatoria usando os.urandom(). Su longitud puede ser configurada.

Las claves se guardan en archivos individuales con nombre definido por el usuario, para su posterior uso en el descifrado.

Lógica del cifrado y descifrado
El código implementa las funciones de cifrado y descifrado de manera simétrica. Primero se lee el archivo de entrada, luego se realiza el cifrado o descifrado, y finalmente se guarda el resultado en el archivo de salida.

Estas funciones se llaman de manera recursiva para procesar directorios enteros.

Interfaz
La interfaz se realiza mediante un menú en consola con opciones numeradas. Solicita como entrada y salida las rutas completas de archivos y directorios, así como la ruta del archivo de claves.

Documentación adicional
Comentarios detallados sobre el funcionamiento interno se incluyen directamente en el código fuente.

## Mejoras futuras

- Validación de parámetros
- Cifrado/descifrado por streams
- Selección de algoritmos y modos de operación
- Manejo de excepciones
