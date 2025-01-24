# Instalação no Linux

## Ubuntu/Debian

### 1. Atualizar Sistema
```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Instalar Ferramentas Básicas
```bash
sudo apt install -y build-essential git cmake
```

### 3. Instalar OpenCL
```bash
sudo apt install -y ocl-icd-opencl-dev opencl-headers
```

### 4. Instalar OpenSSL
```bash
sudo apt install -y libssl-dev
```

### 5. Drivers GPU

#### Para AMD:
```bash
sudo apt install -y amdgpu-pro
# Ou para driver open source:
sudo apt install -y mesa-opencl-icd
```

#### Para NVIDIA:
```bash
# Adicionar repositório
sudo add-apt-repository ppa:graphics-drivers/ppa
sudo apt update
# Instalar driver mais recente
sudo apt install -y nvidia-driver-xxx nvidia-opencl-dev
```

## Arch Linux

### 1. Instalar Dependências Base
```bash
sudo pacman -S base-devel git cmake
```

### 2. Instalar OpenCL e OpenSSL
```bash
sudo pacman -S opencl-icd-loader opencl-headers openssl
```

### 3. Drivers GPU
```bash
# AMD
sudo pacman -S opencl-mesa

# NVIDIA
sudo pacman -S nvidia nvidia-utils opencl-nvidia
``` 