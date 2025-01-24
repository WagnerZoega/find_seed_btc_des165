#include "opencl_manager.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>

void OpenCLManager::initialize() {
    try {
        // Obter plataformas disponíveis
        std::vector<cl::Platform> platforms;
        cl::Platform::get(&platforms);
        if (platforms.empty()) {
            throw std::runtime_error("Nenhuma plataforma OpenCL encontrada");
        }

        // Selecionar primeira plataforma
        cl::Platform platform = platforms[0];

        // Obter dispositivos disponíveis
        std::vector<cl::Device> devices;
        platform.getDevices(CL_DEVICE_TYPE_ALL, &devices);
        if (devices.empty()) {
            throw std::runtime_error("Nenhum dispositivo OpenCL encontrado");
        }

        // Selecionar primeiro dispositivo
        cl::Device device = devices[0];

        // Criar contexto
        context = cl::Context(device);

        // Criar fila de comandos
        queue = cl::CommandQueue(context, device);

    } catch (const cl::Error& e) {
        throw std::runtime_error("Erro OpenCL durante inicialização: " + 
                               std::string(e.what()) + " (" + 
                               std::to_string(e.err()) + ")");
    }
}

void OpenCLManager::loadKernels() {
    try {
        std::string kernel_path = "kernel";
        std::vector<std::string> kernel_files = {
            "main.cl",
            "common.cl",
            "sha256.cl",
            "sha512_hmac.cl",
            "ec.cl",
            "bip39.cl"
        };

        std::string kernel_source;
        for (const auto& file : kernel_files) {
            std::ifstream kernel_file(kernel_path + "/" + file);
            if (!kernel_file.is_open()) {
                throw std::runtime_error("Não foi possível abrir o arquivo: " + file);
            }
            kernel_source += std::string(
                std::istreambuf_iterator<char>(kernel_file),
                std::istreambuf_iterator<char>()
            );
            kernel_file.close();
        }

        // Criar programa a partir do código fonte
        program = cl::Program(context, kernel_source);

        // Compilar programa
        try {
            program.build();
        } catch (const cl::Error& e) {
            // Em caso de erro de compilação, mostrar log
            std::string build_log = program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(
                context.getInfo<CL_CONTEXT_DEVICES>()[0]
            );
            throw std::runtime_error("Erro ao compilar kernels:\n" + build_log);
        }

    } catch (const cl::Error& e) {
        throw std::runtime_error("Erro OpenCL ao carregar kernels: " + 
                               std::string(e.what()) + " (" + 
                               std::to_string(e.err()) + ")");
    }
} 