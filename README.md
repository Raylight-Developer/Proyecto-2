Paralelo:
```bash
mpiexec -np 4 ./Proyecto-2.exe --parallel 0 --sequential 0 --key-gen-mode 0 --key-count 1048576 --key 0x12 0x34 0x56 0x4C 0x00 0x00 0x00 0x00
```
Secuencial:
```bash
./Proyecto-2.exe --parallel 0 --sequential 1 --key-gen-mode 0 --key-count 1048576 --key 0x12 0x34 0x56 0x4C 0x00 0x00 0x00 0x00
```
Ejemplo:
```bash
mpiexec -np 4 ./Proyecto-2.exe --parallel 0 --sequential 0 --key-gen-mode 0 --key 0x12 0x34 0x25 0x00 0x00 0x00 0x00 0x00
```

a.Mida el tiempo de ejecución en romper el código usando la llave 123456L
```bash
mpiexec -np 4 ./Proyecto-2.exe --parallel 1 --sequential 0 --key-gen-mode 0 --key 0x12 0x34 0x56 0x4C 0x00 0x00 0x00 0x00
```