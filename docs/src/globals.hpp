#pragma once
#include <vector>
#include <string>

// Lista de palavras pré-configuradas para busca
extern const std::vector<std::string> FIXED_WORDS;

// Endereço Bitcoin alvo
extern const std::string TARGET_ADDRESS;

// Variáveis de controle
extern bool found_address;
extern bool should_exit;
extern uint64_t current_low;
extern uint64_t current_high;

// Funções de utilidade
void print_progress(uint64_t current, uint64_t total);
void print_found_phrase(const std::vector<std::string>& words);
void print_phrase_info(const std::string& phrase, const std::string& address); 