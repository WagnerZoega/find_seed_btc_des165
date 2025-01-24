# Compilação do Projeto

## Preparação Inicial

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/bitcoin-mnemonic-search.git
cd bitcoin-mnemonic-search/C++
```

## Windows (PowerShell)

1. Criar e entrar na pasta build:
```powershell
Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "build"
cd build
```

2. Configurar com CMake:
```powershell
cmake -DCMAKE_BUILD_TYPE=Release ..
```

3. Compilar:
```powershell
cmake --build . --config Release
```

O executável estará em: `build\Release\bitcoin-mnemonic-search.exe`

## Linux

1. Criar e entrar na pasta build:
```bash
rm -rf build
mkdir build
cd build
```

2. Configurar com CMake:
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
```

3. Compilar:
```bash
make -j$(nproc)
```

O executável estará em: `build/Release/bitcoin-mnemonic-search`

## Verificação da Instalação

Para verificar se a compilação foi bem-sucedida:

1. Windows:
```powershell
.\build\Release\bitcoin-mnemonic-search.exe --version
```

2. Linux:
```bash
./build/Release/bitcoin-mnemonic-search --version
``` 