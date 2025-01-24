# Guia de Uso

## Execução do Programa

### Windows
```powershell
cd build\Release
.\bitcoin-mnemonic-search.exe
```

### Linux
```bash
cd build/Release
./bitcoin-mnemonic-search
```

## Funcionalidades

### 1. Busca de Frases
- O programa busca uma frase mnemônica que gera um endereço Bitcoin específico
- Utiliza 34 palavras pré-definidas em português
- Gera combinações sem repetir palavras na mesma frase
- Processa milhões de combinações por segundo usando GPU

### 2. Monitoramento
O programa mostra a cada 40.5 milhões de tentativas:
- Progresso atual da busca
- Velocidade em frases por segundo
- Frase atual sendo testada
- Endereço Bitcoin gerado
- Informações da carteira (WIF)

### 3. Resultado
Quando encontrar a frase correta, mostrará:
```
=== FRASE ENCONTRADA! ===
Frase: palavra1 palavra2 palavra3 ... palavra12
Endereço: 1EciYvS7FFjSYfrWxsWYjGB8K9BobBfCXw
WIF: 5K...
=======================
```

## Observações Importantes

1. **Performance**
   - A velocidade depende da GPU utilizada
   - Recomendado usar GPU dedicada (não integrada)
   - Manter drivers atualizados

2. **Recursos**
   - O programa usa recursos significativos da GPU
   - Recomendado fechar outros programas pesados
   - Manter temperatura da GPU monitorada

3. **Segurança**
   - Guarde a frase encontrada com segurança
   - O WIF permite acesso completo à carteira
   - Nunca compartilhe a chave privada 