// Arquivo: bip39.cl
// Kernel OpenCL para busca de frases BIP39

// Constantes do alvo
#define TARGET_HIGH 0xA54FF53A5F1D36F1ul
#define TARGET_LOW  0x510E527FADE682D1ul

// Macros para operações SHA512
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define ROTR64(x,n) rotate(x, (ulong)(64-n))
#define SHR(x,n)    (x >> n)
#define SIGMA0(x) (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define SIGMA1(x) (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define sigma0(x) (ROTR64(x,1)  ^ ROTR64(x,8)  ^ SHR(x,7))
#define sigma1(x) (ROTR64(x,19) ^ ROTR64(x,61) ^ SHR(x,6))

// Constantes SHA512
__constant ulong k[] = {
    0x428a2f98d728ae22ul, 0x7137449123ef65cdul,
    0xb5c0fbcfec4d3b2ful, 0xe9b5dba58189dbbcul,
    0x3956c25bf348b538ul, 0x59f111f1b605d019ul,
    0x923f82a4af194f9bul, 0xab1c5ed5da6d8118ul,
    0xd807aa98a3030242ul, 0x12835b0145706fbel,
    0x243185be4ee4b28cul, 0x550c7dc3d5ffb4e2ul,
    0x72be5d74f27b896ful, 0x80deb1fe3b1696b1ul,
    0x9bdc06a725c71235ul, 0xc19bf174cf692694ul
};

// Função para gerar frase
void generate_phrase(ulong id, __global uint* phrase) {
    // Array para controlar palavras disponíveis
    uint available[34];
    uint num_available = 34;
    
    // Inicializar array de palavras disponíveis
    for(uint i = 0; i < 34; i++) {
        available[i] = i;
    }
    
    // Usar o id como semente para gerar números pseudo-aleatórios
    ulong seed = id;
    
    // Gerar cada palavra da frase
    for(int i = 0; i < 12; i++) {
        // Gerar próximo número pseudo-aleatório
        seed = seed * 6364136223846793005UL + 1;
        
        // Selecionar índice aleatório das palavras disponíveis
        uint idx = (uint)(seed >> 32) % num_available;
        
        // Usar a palavra selecionada
        phrase[i] = available[idx];
        
        // Remover palavra usada movendo a última palavra disponível para esta posição
        available[idx] = available[num_available - 1];
        num_available--;
    }
}

// Função para calcular hash SHA512
void calculate_hash(const ulong* input, ulong* output) {
    ulong state[8] = {
        0x6a09e667f3bcc908ul,
        0xbb67ae8584caa73bul,
        0x3c6ef372fe94f82bul,
        0xa54ff53a5f1d36f1ul,
        0x510e527fade682d1ul,
        0x9b05688c2b3e6c1ful,
        0x1f83d9abfb41bd6bul,
        0x5be0cd19137e2179ul
    };
    
    ulong w[80];
    
    // Copiar input para w
    for(int i = 0; i < 16; i++) {
        w[i] = input[i];
    }
    
    // Expandir mensagem
    for(int i = 16; i < 80; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    
    // Comprimir
    ulong a = state[0];
    ulong b = state[1];
    ulong c = state[2];
    ulong d = state[3];
    ulong e = state[4];
    ulong f = state[5];
    ulong g = state[6];
    ulong h = state[7];
    
    for(int i = 0; i < 80; i++) {
        ulong t1 = h + SIGMA1(e) + CH(e,f,g) + k[i] + w[i];
        ulong t2 = SIGMA0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    output[0] = state[0] + a;
    output[1] = state[1] + b;
}

// Kernel principal
__kernel void verify(__global const uint* fixed_words,
                    __global ulong* result,
                    __global uint* found_words) {
    size_t id = get_global_id(0);
    
    // Gerar frase e salvar índices a cada 200.5 milhões de tentativas
    if (id % 200500000 == 0) {
        generate_phrase(id, found_words);
        result[1] = 1;  // Sinalizar que há uma frase para mostrar
    }
    
    // Gerar seed a partir da frase
    ulong block[16] = {0};
    generate_phrase(id, found_words);
    
    // Calcular hash
    ulong hash[2];
    calculate_hash(block, hash);
    
    // Verificar se encontramos o endereço
    if (hash[0] == TARGET_HIGH && hash[1] == TARGET_LOW) {
        result[0] = id;
    }
}