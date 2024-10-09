```bash
mpiexec -np 8 ./Proyecto-2.exe --parallel 0 --sequential 0 --key-gen-mode 0 --key-count 1048576 --key 0xFF 0xFF 0x03 0x00 0x00 0x00 0x00 0x00
```

# Proyecto de Fuerza Bruta DES con MPI

Este proyecto implementa un ataque de fuerza bruta sobre el algoritmo de cifrado DES (Data Encryption Standard) utilizando paralelización con MPI para mejorar la eficiencia de la búsqueda de la clave.

## Descripción del Proyecto

El objetivo de este proyecto es cifrar y descifrar un texto utilizando el algoritmo DES y probar un rango de claves para romper la encriptación mediante fuerza bruta. El programa puede ejecutarse en modo paralelo o secuencial para analizar la eficiencia y el rendimiento de la paralelización.

### Características Principales

1. **Modo Secuencial y Paralelo**: El programa puede ejecutarse en modo secuencial o en paralelo utilizando MPI.
2. **Generación de Claves**: Admite varios modos de generación de claves, incluyendo claves ascendentes, descendentes, con pasos específicos o aleatorias.
3. **Métricas de Desempeño**: Calcula el tiempo de ejecución, Speedup, Eficiencia y Efectividad para analizar el rendimiento.

## Requisitos

- `g++` (compilador de C++)
- MPI
- Windows con soporte para la API `BCrypt`
- Biblioteca `Crypt.hpp`

## Compilación

Para compilar el proyecto, use el siguiente comando:

```bash
g++ -fdiagnostics-color=always -g main.cpp -o Proyecto-2.exe -I "C:/Program Files (x86)/Microsoft SDKs/MPI/Include" -L "C:/Program Files (x86)/Microsoft SDKs/MPI/Lib/x64" -lmsmpi -lbcrypt

