# 🚀 Otimização de Busca Bitcoin Usando OpenCL

Este relatório detalha o processo de otimização de um kernel OpenCL projetado para recuperar seeds de carteira Bitcoin. O cenário envolve a reconstrução de uma frase mnemônica BIP-39 usando um conjunto específico de palavras em português.

---

## 🎯 Definição do Problema

O desafio consiste em encontrar uma frase mnemônica BIP39 específica de 12 palavras que gera um endereço Bitcoin alvo X, A busca é limitada a 34 palavras pré-definidas em português:

```
inocente, baseado, global, cadeado, camada, uniforme,
nordeste, desafio, entanto, devido, treino, sonegar,
dinheiro, criminal, negativa, pessoa, zangado, tarefa,
quase, manter, mestre, ativo, visto, mais, tabela,
clareza, perfeito, moeda, verdade, clone, enquanto,
chave, busca, artigo
```

O programa deve gerar combinações dessas palavras (sem repetição) até encontrar a frase correta que produz o endereço alvo.

**Especificações**
---
PLACA USADA COM O CÓDIGO - AMD Radeon RX550/550 4GB - 40mi seed/sec
NVIDIA GeForce RTX 3060 Ti / 300k mi seed/sec
NVIDIA GeForce RTX 4090 / 1.8mi seed/sec
NVIDIA GeForce RTX 4080 S / 1.0mi seed/sec
NVIDIA GeForce RTX 4070 S TI / 750l seed/sec
NVIDIA GeForce RTX 4060 Ti / 400k seed/sec
NVIDIA GeForce RTX 1070 / 80k seed/sec
NVIDIA GeForce RTX 3060 / 230k seed/sec

## Características
- Processamento paralelo em GPU via OpenCL
- Geração de frases sem repetição de palavras
- Implementação BIP39 e BIP44 (m/44'/0'/0'/0/0)
- Geração de endereços Bitcoin comprimidos
- Interface em português
- Otimizado para GPUs AMD e NVIDIA

## Documentação
1. [Requisitos do Sistema](docs/1-REQUISITOS.md)
2. [Instalação Windows](docs/2-INSTALACAO_WINDOWS.md)
3. [Instalação Linux](docs/3-INSTALACAO_LINUX.md)
4. [Compilação](docs/4-COMPILACAO.md)
5. [Uso do Programa](docs/5-USO.md)
6. [Solução de Problemas](docs/6-TROUBLESHOOTING.md)

## Compilação Rápida

Windows (PowerShell):
```powershell
rmdir /s /q build; mkdir build; cd build; cmake -DCMAKE_BUILD_TYPE=Release ..; cmake --build . --config Release
```

Linux:
```bash
rm -rf build && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
```

## Licença
Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🛠️ Otimizações

### 1. Representação Eficiente de Mnemônicos com Manipulação de Bits

## 🌟 Conclusão

Este projeto demonstra o poder da aceleração GPU e otimização de kernel na resolução de desafios computacionalmente intensivos. Com estas técnicas, alcançamos um excelente desempenho na recuperação de seeds Bitcoin.

Sinta-se à vontade para contribuir, sugerir melhorias ou abrir uma issue se tiver alguma ideia.

**Saudações**

projeto baseado em https://github.com/ipsbrunoreserva/bitcoin_cracking 
