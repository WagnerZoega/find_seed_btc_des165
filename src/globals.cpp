#include "globals.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

// Lista de 34 palavras pré-configuradas para busca
const std::vector<std::string> FIXED_WORDS = {
    "inocente", "baseado", "global", "cadeado", "camada", "uniforme",
    "nordeste", "desafio", "entanto", "devido", "treino", "sonegar",
    "dinheiro", "criminal", "negativa", "pessoa", "zangado", "tarefa",
    "quase", "manter", "mestre", "ativo", "visto", "mais", "tabela",
    "clareza", "perfeito", "moeda", "verdade", "clone", "enquanto",
    "chave", "busca", "artigo"
};

const std::string TARGET_ADDRESS = "1EciYvS7FFjSYfrWxsWYjGB8K9BobBfCXw"; 

bool found_address = false;
bool should_exit = false;
uint64_t current_low = 0;
uint64_t current_high = 0; 

void print_progress(uint64_t current, uint64_t total) {
    double percentage = (current * 100.0) / total;
    std::cout << "\rProgresso: " << current << "/" << total 
              << " (" << std::fixed << std::setprecision(2) << percentage << "%)" << std::flush;
}

void print_found_phrase(const std::vector<std::string>& words) {
    std::cout << "\nFrase encontrada:" << std::endl;
    for (const auto& word : words) {
        std::cout << word << " ";
    }
    std::cout << std::endl;
}

void print_phrase_info(const std::string& phrase, const std::string& address) {
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "Frase: " << phrase << std::endl;
    std::cout << "Endereço: " << address << std::endl;
    std::cout << "----------------------------------------\n" << std::endl;
} 