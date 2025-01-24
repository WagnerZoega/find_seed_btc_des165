# Instalação no Windows

## 1. Visual Studio 2022
1. Baixe o [Visual Studio 2022 Community](https://visualstudio.microsoft.com/downloads/)
2. Durante a instalação, selecione:
   - Desenvolvimento para Desktop com C++
   - Suporte ao CMake
   - Ferramentas de build C++

## 2. OpenCL SDK
1. Baixe o [OpenCL SDK](https://github.com/KhronosGroup/OpenCL-SDK/releases)
2. Extraia para `C:\Program Files\OpenCL-SDK`
3. Adicione ao PATH do sistema:
   ```
   C:\Program Files\OpenCL-SDK\bin
   C:\Program Files\OpenCL-SDK\lib
   ```

## 3. OpenSSL
1. Baixe o [OpenSSL para Windows](https://slproweb.com/products/Win32OpenSSL.html)
2. Escolha a versão 64-bit
3. Instale em `C:\Program Files\OpenSSL-Win64`
4. Marque a opção para adicionar ao PATH

## 4. CMake
1. Baixe o [CMake](https://cmake.org/download/)
2. Durante a instalação:
   - Selecione "Add CMake to system PATH"
   - Escolha "Add for all users"

## 5. Drivers GPU
- AMD: [AMD Software: Adrenalin Edition](https://www.amd.com/en/support)
- NVIDIA: [NVIDIA Drivers](https://www.nvidia.com/download/index.aspx) 