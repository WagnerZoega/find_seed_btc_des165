# Solução de Problemas

## Problemas Comuns

### 1. Erro de OpenCL
```
Erro: Nenhuma plataforma OpenCL encontrada
```
**Solução:**
- Verificar se os drivers da GPU estão instalados
- Reinstalar drivers da GPU
- Verificar se OpenCL SDK está instalado corretamente

### 2. Erro de Compilação
```
CMake Error: ...
```
**Solução:**
- Verificar se todas as dependências estão instaladas
- Confirmar versão do CMake (3.10+)
- Limpar pasta build e recompilar

### 3. Erro de OpenSSL
```
Error: Cannot find OpenSSL
```
**Solução:**
- Reinstalar OpenSSL
- Verificar variáveis de ambiente
- Confirmar se libssl-dev está instalado (Linux)

### 4. Baixa Performance
**Solução:**
- Atualizar drivers da GPU
- Verificar temperatura da GPU
- Fechar aplicações em segundo plano
- Usar GPU dedicada em vez de integrada

## Verificações

### Windows
1. Verificar OpenCL:
```powershell
clinfo
```

2. Verificar OpenSSL:
```powershell
openssl version
```

### Linux
1. Verificar OpenCL:
```bash
clinfo
```

2. Verificar OpenSSL:
```bash
openssl version
```

## Contato e Suporte

Se encontrar problemas não listados aqui:
1. Abra uma issue no GitHub
2. Forneça:
   - Logs de erro
   - Sistema operacional
   - Modelo da GPU
   - Versões dos drivers 