# 🚀 Optimized Bitcoin Cracking Using OpenCL

This report details the optimization process for an OpenCL kernel designed to recover Bitcoin wallet seeds. The scenario involves reconstructing a **BIP-39 mnemonic** with only 7 out of the 12 words known. The challenge required handling a search space exceeding **2.2 quadrillion possibilities** while achieving extreme computational efficiency



---

## 🎯 Problem Statement

The challenge involves finding a specific 12-word BIP39 mnemonic phrase that generates a target Bitcoin address (1EciYvS7FFjSYfrWxsWYjGB8K9BobBfCXw). The search space is limited to 34 predefined Portuguese words:

```
inocente, baseado, global, cadeado, camada, uniforme,
nordeste, desafio, entanto, devido, treino, sonegar,
dinheiro, criminal, negativa, pessoa, zangado, tarefa,
quase, manter, mestre, ativo, visto, mais, tabela,
clareza, perfeito, moeda, verdade, clone, enquanto,
chave, busca, artigo
```

The program must generate combinations of these words (without repetition) until finding the correct phrase that produces the target address.

To tackle this challenge, aggressive optimizations were applied to the kernel, focusing on memory efficiency, loop unrolling, and minimizing computational overhead. The result was a NVIDIA 4090TI **validation rate of 2 million valids seeds per second**.

**Specs**
---
PLACA USADA COM O CODIGO - AMD Radeon RX550/550 4GB - 40mi seed/sec
NVIDIA GeForce RTX 3060 Ti / 300k mi seed/sec
NVIDIA GeForce RTX 4090 / 1.8mi seed/sec
NVIDIA GeForce RTX 4080 S / 1.0mi seed/sec
NVIDIA GeForce RTX 4070 S TI / 750l seed/sec
NVIDIA GeForce RTX 4060 Ti / 400k seed/sec
NVIDIA GeForce RTX 1070 / 80k seed/sec
NVIDIA GeForce RTX 3060 / 230k seed/sec


#### Exploring the Vastness of 5 Words

- Quadrillion is not just a number; it symbolizes the monumental scale of data and probabilities in our digital era. To grasp its magnitude:

- Staggering Storage: The storage for comprehensive cryptocurrency wallets adds up to about 220 million terabytes. If each terabyte were a kilometer, this would be enough to travel from Earth to the Sun over 600 times

- Astronomical Odds: The likelihood of guessing a single private hash in the blockchain is far lower than winning the lottery 40 billion times consecutively.

- It highlights the incredible security embedded within modern cryptographic systems. Data in Daily Life: On a daily basis, the world generates about 2.5 quintillion bytes of data. 2 quadrillion is a stepping stone toward this daily generation, showing how quickly data accumulates in the age of the internet.

- Cosmic Comparisons: If each of the 2 quadrillion units were a star, they would outnumber all the stars in our galaxy, which is estimated to hold about 100 to 400 billion stars.

- The Future of Technology: The figure 2 quadrillion is a benchmark that challenges us to continuously evolve our digital infrastructures and cryptographic technologies. As we push the boundaries of what is possible, the numbers that once seemed unreachable become part of our everyday reality, urging us to innovate and secure the digital cosmos


## 🛠️ Optimizations


### 1. Efficient Mnemonic Representation with Bit Manipulation

Instead of treating mnemonics as strings, they are represented as **bit-masked indices** stored in `ulong` variables. This allowed faster calculations and reduced computational overhead. The indices are extracted using shifts and bitwise operations.

```c
indices[0] = (seed_max & (2047UL << 53UL)) >> 53UL;
indices[1] = (seed_max & (2047UL << 42UL)) >> 42UL;
indices[2] = (seed_max & (2047UL << 31UL)) >> 31UL;
indices[3] = (seed_max & (2047UL << 20UL)) >> 20UL;
indices[4] = (seed_max & (2047UL << 9UL)) >> 9UL;
indices[5] = (((seed_max << 55UL) >> 53UL)) | (((seed_min & (3UL << 62UL)) >> 62UL));
indices[6] = (seed_min & (2047UL << 51UL)) >> 51UL;

Thank you John Cantrell
```

### 2. Loop Unrolling Ever

The computation of SHA-256 was heavily optimized by unrolling loops and eliminating conditional checks. The final loop iteration was avoided, as only `H0/A` was required for validation.

```c
#pragma unroll
for (int i = 0; i < 63; ++i) {
    temp1 = h + ((ROTR_256(e, 6)) ^ (ROTR_256(e, 11)) ^ (ROTR_256(e, 25))) +
            ((e & f) ^ (~e & g)) + K_256[i] + w[i];
    temp2 = ((ROTR_256(a, 2)) ^ (ROTR_256(a, 13)) ^ (ROTR_256(a, 22))) +
            ((a & b) ^ (a & c) ^ (b & c));

```



#### 3. Optimized SHA-512 Memory Usage in 64 Bits
The SHA-512 implementation was optimized to operate on smaller memory buffers using ulong arrays. This reduced the loop execution from 128 iterations to just 16 per block

![image](https://github.com/user-attachments/assets/c1dded49-ae06-43a2-af4a-6c1bb4e96c01)



#### 4. Vectors
Tricks with 8 and 16 byte vectors allow us to make copies of data faster

![image](https://github.com/user-attachments/assets/3e17d263-6f66-4ae1-8dce-031dba54504e)


#### 5. Pre-calculate the Hashes of the First 7 Fixed Words  (To-do)
Since the first mnemonics remain unchanged, the SHA-512/SHA-256 values can be precomputed and reused. This eliminates the need for recalculating the same values repeatedly, effectively doubling the search speed.

#### 6. Power of multi-threading in Python to control memory resources and manage database connections, developers must adhere


## 🚀 Results

-   **Performance**: Achieved **12 billions seed validations per second in SH256**, leveraging GPU parallelism and **3 billions SHA-512 ops with a aggressive kernel optimization.
-   **Memory Efficiency**: Reduced memory usage by consolidating data structures and minimizing array sizes with Python management.
-   **Scalability**: Fully parallelized OpenCL kernels are ready for multi-GPU setups to scale performance further.



## 🔮 Future Directions

1. **Add Multi-GPU Support**  
   Expand kernel support for multi-GPU configurations to further enhance scalability and processing speed. This will allow distributed workloads across multiple GPUs, increasing the validation throughput significantly.

2. **Address Derivation and Comparison**  
   Extend the implementation to not only perform PBKDF2-HMAC-SHA512 but also derive **public addresses** based on the user-defined derivation path (e.g., BIP-32 or BIP-44 standards). The derived addresses will then be compared against the user-provided Bitcoin or cryptocurrency address to identify the correct mnemonic.

   Steps for this feature:
   - Implement BIP-32/BIP-44 derivation logic after generating the master private key.
   - Derive child keys for the specified derivation path.
   - Compute public keys and addresses for each child key.
   - Compare derived addresses with the user-provided address to validate the mnemonic.
   - Compare addresses with **ALL** blockchain data

----------

## 🌟 Conclusion

This project showcases the power of GPU acceleration and kernel optimization in solving computationally intensive challenges. With these techniques, we achieved a very good performance in Bitcoin seed recovery.

Feel free to contribute, suggest improvements, or open an issue if you have any ideas. 


**Regards**

based project: https://github.com/ipsbrunoreserva/bitcoin_cracking

