#define CL_HPP_ENABLE_EXCEPTIONS
#define CL_HPP_TARGET_OPENCL_VERSION 200
#define CL_HPP_MINIMUM_OPENCL_VERSION 200
#include <CL/opencl.hpp>
#include "globals.hpp"
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <random>
#include <filesystem>
#include <algorithm>
#include <iomanip>  // para std::fixed e std::setprecision
#include "bitcoin_utils.hpp"
#include "bip39_utils.hpp"
#include <sstream>
// Incluir cabeçalhos específicos do sistema operacional para caminhos
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif
#include <chrono>
#include <set>

using namespace cl;  // Adicionar o namespace cl

// Função auxiliar para obter o caminho do executável
std::string get_executable_path() {
    return std::filesystem::current_path().string();
}

// Função auxiliar para ler arquivo
std::string read_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Não foi possível abrir o arquivo: " + filename);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Função para verificar resultado
    void verifyResult(uint64_t result) {
        // Converter o resultado para frase
        std::vector<int> indices;
        for(int i = 0; i < 12; i++) {
            indices.push_back((result >> (i * 5)) & 0x1F);
        }
        
        // Construir a frase
        std::string frase;
        for(size_t i = 0; i < indices.size(); i++) {
            if(i > 0) frase += " ";
            frase += FIXED_WORDS[indices[i]];
        }
        
        // Gerar seed e derivar endereço
        auto seed = BIP39Utils::mnemonic_to_seed(frase);
        auto private_key = BitcoinUtils::derive_private_key(seed);
    std::string wif = BitcoinUtils::private_key_to_wif(private_key);
        std::string endereco = BitcoinUtils::derive_address(private_key);
        
        // Verificar se encontrou
        if(endereco == TARGET_ADDRESS) {
            std::cout << "\n=== FRASE ENCONTRADA! ===" << std::endl;
        std::cout << "Frase: " << frase << std::endl;
        std::cout << "Endereço: " << endereco << std::endl;
        std::cout << "WIF: " << wif << std::endl;  // Mostrar WIF apenas quando encontrar
        std::cout << "=======================" << std::endl;
        found_address = true;
        should_exit = true;
    }
}

// Função para testar uma carteira específica
void test_wallet() {
    std::cout << "\n=== Teste de Carteira ===" << std::endl;
    
    try {
        // Teste 1: Frase fixa para verificação
        std::string frase_fixa = "artigo ativo busca baseado cadeado camada chave clareza clone criminal desafio devido";
        std::cout << "\n1. Teste com frase fixa:" << std::endl;
        std::cout << "Frase: " << frase_fixa << std::endl;
        
        auto seed1 = BIP39Utils::mnemonic_to_seed(frase_fixa);
        auto private_key1 = BitcoinUtils::derive_private_key(seed1);
        std::string wif1 = BitcoinUtils::private_key_to_wif(private_key1);
        std::string endereco1 = BitcoinUtils::derive_address(private_key1);
        
        std::cout << "WIF: " << wif1 << std::endl;
        std::cout << "Endereço: " << endereco1 << std::endl;
        
        // Teste 2: Frase aleatória usando nossas palavras
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, FIXED_WORDS.size() - 1);
    
        std::string frase_aleatoria;
        for(int i = 0; i < 12; i++) {
            if(i > 0) frase_aleatoria += " ";
            frase_aleatoria += FIXED_WORDS[dis(gen)];
        }
        
        std::cout << "\n2. Teste com frase aleatória:" << std::endl;
        std::cout << "Frase: " << frase_aleatoria << std::endl;
        
        auto seed2 = BIP39Utils::mnemonic_to_seed(frase_aleatoria);
        auto private_key2 = BitcoinUtils::derive_private_key(seed2);
        std::string wif2 = BitcoinUtils::private_key_to_wif(private_key2);
        std::string endereco2 = BitcoinUtils::derive_address(private_key2);
        
        std::cout << "WIF: " << wif2 << std::endl;
        std::cout << "Endereço: " << endereco2 << std::endl;
        
        // Teste 3: Verificar carteira alvo
        std::cout << "\n3. Carteira alvo para busca:" << std::endl;
        std::cout << "Endereço alvo: " << TARGET_ADDRESS << std::endl;
        std::cout << "\nTestes concluídos com sucesso!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Erro no teste: " << e.what() << std::endl;
    }
}

int main() {
    // Configurar console para UTF-8
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "Iniciando programa..." << std::endl;

    try {
        // Primeiro executar o teste
        test_wallet();
        
        std::cout << "\nPressione Enter para iniciar a busca...";
        std::cin.get();
        
        // Iniciar a busca com as 34 palavras
        std::cout << "\n=== Iniciando busca por carteira ===" << std::endl;
        std::cout << "Usando " << FIXED_WORDS.size() << " palavras pré-configuradas." << std::endl;
        
        // Obter caminho do executável
        std::string kernelPath = "kernel/";

        // Usando o namespace cl para acessar as classes e funções do OpenCL
        // Obter plataformas disponíveis
        std::vector<Platform> platforms;
        Platform::get(&platforms);
        std::cout << "Plataformas OpenCL disponíveis: " << platforms.size() << std::endl;
        
        // Mostrar informações das plataformas
        for(const auto& platform : platforms) {
            std::cout << "Plataforma: " << platform.getInfo<CL_PLATFORM_NAME>() << std::endl;
            std::cout << "Versão: " << platform.getInfo<CL_PLATFORM_VERSION>() << std::endl;
        }

        // Selecionar a primeira plataforma disponível
        if(platforms.empty()) {
            throw std::runtime_error("Nenhuma plataforma OpenCL encontrada");
        }
        Platform platform = platforms[0];

        // Obter dispositivos GPU
        std::vector<Device> devices;
        platform.getDevices(CL_DEVICE_TYPE_GPU, &devices);
        
        if(devices.empty()) {
            std::cout << "Nenhum dispositivo GPU encontrado, tentando CPU..." << std::endl;
            platform.getDevices(CL_DEVICE_TYPE_CPU, &devices);
            if(devices.empty()) {
                throw std::runtime_error("Nenhum dispositivo OpenCL encontrado");
            }
        }

        // Mostrar informações dos dispositivos
        for(const auto& device : devices) {
            std::cout << "Dispositivo: " << device.getInfo<CL_DEVICE_NAME>() << std::endl;
            std::cout << "Versão OpenCL: " << device.getInfo<CL_DEVICE_VERSION>() << std::endl;
        }

        // Criar contexto com o primeiro dispositivo
        Context context({devices[0]});
        CommandQueue queue(context);

        std::vector<std::string> kernel_sources;
        
        // Carregar common.cl primeiro
        std::ifstream ifs_common(kernelPath + "common.cl");
        if (!ifs_common.is_open()) {
            throw std::runtime_error("Não foi possível abrir common.cl");
        }
        std::string common_content((std::istreambuf_iterator<char>(ifs_common)), 
                                 (std::istreambuf_iterator<char>()));
        std::cout << "common.cl carregado com " << common_content.length() << " bytes" << std::endl;
        
        // Ler código fonte do kernel
        std::string kernel_code = read_file("kernel/bip39.cl");
        
        // Criar fontes do programa
        cl::Program::Sources sources;
        sources.push_back({kernel_code.c_str(), kernel_code.length()});
        
        // Criar programa OpenCL
        std::cout << "Criando programa OpenCL..." << std::endl;
        cl::Program program(context, sources);
        
        // Salvar o código fonte para debug
        std::ofstream debug_file("debug_kernel.cl");
        debug_file << kernel_code;
        debug_file.close();
        
        // Compilar programa
        std::cout << "Compilando programa OpenCL..." << std::endl;
        try {
            program.build({devices[0]});
        } catch (const cl::Error& e) {
            std::cerr << "Log de erro de compilação para " << devices[0].getInfo<CL_DEVICE_NAME>() << ":" << std::endl
                     << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(devices[0]) << std::endl;
            throw e;
        }
        
        std::cout << "Criando kernel..." << std::endl;
        Kernel kernel(program, "verify");
        std::cout << "Kernel criado com sucesso!" << std::endl;
        
        // Criar buffer para palavras fixas
        std::vector<uint32_t> fixed_words_vec;
        fixed_words_vec.reserve(FIXED_WORDS.size());
        
        // Converter strings para números
        for (const auto& word : FIXED_WORDS) {
            // Hash simples da palavra para uint32_t
            uint32_t hash = 0;
            for (char c : word) {
                hash = hash * 31 + c;
            }
            fixed_words_vec.push_back(hash);
        }
        
        std::cout << "Criando buffer de palavras fixas..." << std::endl;
        Buffer fixedWordsBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                             sizeof(uint32_t) * fixed_words_vec.size(),
                             fixed_words_vec.data());
        
        std::cout << "Alocando buffer de resultado..." << std::endl;
        Buffer resultBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_ulong) * 2);
        Buffer foundWordsBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 12);
        std::cout << "Buffer alocado com sucesso!" << std::endl;
        
        // Calcular total de combinações
        uint64_t total_combinations = 1;
        for(uint64_t i = 34; i > 34-12; i--) {
            total_combinations *= i;
        }
        
        // Configurar tamanhos de trabalho
        size_t local_size = 256;
        
        std::cout << "Total de combinações possíveis: " << total_combinations 
                  << " (34C12 = 34!/(12! * 22!))" << std::endl;
        std::cout << "Iniciando busca..." << std::endl << std::endl;
        
        std::cout << "Configurando argumentos do kernel..." << std::endl;
        kernel.setArg(0, fixedWordsBuffer);
        kernel.setArg(1, resultBuffer);
        kernel.setArg(2, foundWordsBuffer);
        std::cout << "Argumentos configurados com sucesso!" << std::endl;
        
        // Variáveis para controle do progresso
        size_t total_tested = 0;
        const size_t progress_interval = 40500000; // Mostrar progresso a cada 40.5M tentativas
        
        // Função auxiliar para gerar frase de exemplo
        auto generate_phrase = [](uint64_t index, const uint32_t* words, uint32_t* phrase) {
            uint64_t remaining = index;
            uint32_t used_words = 0;
            
            for(int i = 0; i < 12; i++) {
                uint32_t word_idx = remaining % (34 - i);
                remaining /= (34 - i);
                
                uint32_t count = 0;
                for(uint32_t w = 0; w < 34; w++) {
                    if(!(used_words & (1U << w))) {
                        if(count == word_idx) {
                            phrase[i] = w;
                            used_words |= (1U << w);
                            break;
                        }
                        count++;
                    }
                }
            }
        };
        
        // Variáveis para cálculo de velocidade
        auto start_time = std::chrono::high_resolution_clock::now();
        uint64_t last_count = 0;
        
        // Loop principal
        while (!should_exit && total_tested < total_combinations) {
            size_t remaining = total_combinations - total_tested;
            size_t batch_size = (remaining < (256ULL * 4096ULL)) ? remaining : (256ULL * 4096ULL);
            batch_size = (batch_size / local_size) * local_size;
            
            if (batch_size == 0) break;  // Evitar erro quando batch_size < local_size
            
            cl::NDRange global(batch_size);
            cl::NDRange local(local_size);
            
            if (total_tested % progress_interval == 0) {
                std::cout << "\rProgresso: " << total_tested << "/" << total_combinations 
                         << " (" << std::fixed << std::setprecision(2) 
                         << (total_tested * 100.0 / total_combinations) << "%)";
                
                // Mostrar exemplo de frase sendo testada
                std::vector<cl_uint> example_words(12);
                generate_phrase(total_tested, fixed_words_vec.data(), example_words.data());
                std::cout << "\nTestando frase: ";
                for (int i = 0; i < 12; i++) {
                    std::cout << FIXED_WORDS[example_words[i]] << " ";
                }
                std::cout << "\nEndereço alvo: " << TARGET_ADDRESS << std::endl << std::endl;
                std::cout.flush();
            }
            
            try {
                queue.enqueueNDRangeKernel(kernel, cl::NullRange, global, local);
                queue.finish();
                
                // Ler resultados
                std::vector<cl_ulong> result(2);
                std::vector<cl_uint> found_words(12);
                queue.enqueueReadBuffer(resultBuffer, CL_TRUE, 0, sizeof(cl_ulong) * 2, result.data());
                queue.enqueueReadBuffer(foundWordsBuffer, CL_TRUE, 0, sizeof(cl_uint) * 12, found_words.data());
                
                // Verificar se encontrou
                if (result[0] != 0) {
                    // Construir frase encontrada
                    std::string frase;
                    for(int i = 0; i < 12; i++) {
                        if(i > 0) frase += " ";
                        frase += FIXED_WORDS[found_words[i]];
                    }
                    
                    // Gerar seed e chaves
                    auto seed = BIP39Utils::mnemonic_to_seed(frase);
                    auto private_key = BitcoinUtils::derive_private_key(seed);
                    std::string wif = BitcoinUtils::private_key_to_wif(private_key);
                    std::string endereco = BitcoinUtils::derive_address(private_key);
                    
                    std::cout << "\n=== FRASE ENCONTRADA! ===" << std::endl;
                    std::cout << "Frase: " << frase << std::endl;
                    std::cout << "Endereço: " << endereco << std::endl;
                    std::cout << "WIF: " << wif << std::endl;
                    std::cout << "=======================" << std::endl;
                    
                    found_address = true;
                    break;
                }
                
                // Mostrar progresso a cada 100.000 tentativas
                if (result[1] == 1) {
                    // Construir frase atual
                    std::string frase;
                    std::set<std::string> palavras_usadas; // Para verificar repetições
                    bool tem_repeticao = false;
                    
                    for(int i = 0; i < 12; i++) {
                        if(i > 0) frase += " ";
                        std::string palavra = FIXED_WORDS[found_words[i]];
                        frase += palavra;
                        
                        // Verificar se a palavra já foi usada
                        if(!palavras_usadas.insert(palavra).second) {
                            tem_repeticao = true;
                            std::cout << "\nAVISO: Palavra repetida: " << palavra << std::endl;
                        }
                    }
                    
                    if(tem_repeticao) {
                        std::cout << "\nAVISO: Frase contém palavras repetidas!" << std::endl;
                        std::cout << "ID: " << total_tested << std::endl;
                        std::cout << "Frase: " << frase << std::endl;
                        std::cout << "Índices: ";
                        for(int i = 0; i < 12; i++) {
                            std::cout << found_words[i] << " ";
                        }
                        std::cout << std::endl;
                    }
                    
                    // Gerar seed e chaves
                    auto seed = BIP39Utils::mnemonic_to_seed(frase);
                    auto private_key = BitcoinUtils::derive_private_key(seed);
                    std::string wif = BitcoinUtils::private_key_to_wif(private_key);
                    std::string endereco = BitcoinUtils::derive_address(private_key);
                    
                    // Calcular velocidade
                    auto current_time = std::chrono::high_resolution_clock::now();
                    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
                    if (time_diff > 0) {
                        uint64_t phrases_per_second = (total_tested - last_count) / time_diff;
                        last_count = total_tested;
                        start_time = current_time;
                        
                        std::cout << "\n----------------------------------------" << std::endl;
                        std::cout << "Progresso: " << total_tested << "/" << total_combinations 
                                  << " (" << std::fixed << std::setprecision(2) 
                                  << (total_tested * 100.0 / total_combinations) << "%)" << std::endl;
                        std::cout << "Velocidade: " << phrases_per_second << " frases/s" << std::endl;
                        std::cout << "Frase atual: " << frase << std::endl;
                        std::cout << "Endereço: " << endereco << std::endl;
                        std::cout << "WIF: " << wif << std::endl;
                        std::cout << "----------------------------------------\n" << std::endl;
                    }
                    result[1] = 0;  // Resetar flag
                }
                
                total_tested += batch_size;
                
            } catch (const Error& e) {
                std::cerr << "Erro OpenCL: " << e.what() << " (código: " << e.err() << ")" << std::endl;
                std::cerr << "Detalhes adicionais:" << std::endl;
                std::cerr << "- Tamanho do lote: " << batch_size << std::endl;
                std::cerr << "- Tamanho do grupo local: " << local_size << std::endl;
                std::cerr << "- Total testado: " << total_tested << std::endl;
                if (e.err() == CL_INVALID_GLOBAL_OFFSET) {
                    std::cerr << "Erro de offset global inválido - tentando continuar..." << std::endl;
                    continue;
                }
                throw; // Re-lançar erro para debug
            }
        }
        
        if (total_tested >= total_combinations) {
            std::cout << "\nBusca concluída. Nenhuma correspondência encontrada." << std::endl;
        }

    } catch (const Error& e) {
        std::cerr << "Erro OpenCL: " << e.what() << " (" << e.err() << ")" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
    }

    // Pausar antes de sair
        std::cout << "\nPressione Enter para sair...";
        std::cin.get();

    return 0;
}