cmake_minimum_required(VERSION 3.10)

# Remover referência ao vcpkg se não estiver usando
# set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Definir o projeto apenas com C++
project(bitcoin-mnemonic-search CXX)

# Definir o padrão C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Encontrar OpenCL e OpenSSL
find_package(OpenCL REQUIRED)
find_package(OpenSSL REQUIRED)

# Adicionar diretórios de include
include_directories(${CMAKE_SOURCE_DIR}/OpenCL-SDK/include)
include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(${OpenCL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})

# Adicionar arquivos fonte
add_executable(${PROJECT_NAME}
    src/main.cpp
    src/globals.cpp
    src/bitcoin_utils.cpp
)

# Linkar bibliotecas
target_link_libraries(${PROJECT_NAME} PRIVATE
    ${OpenCL_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Configurar Release
set(CMAKE_BUILD_TYPE Release)
if(MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
endif()

# Copiar arquivos do kernel
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/Release/kernel"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/src/kernel"
        "${CMAKE_BINARY_DIR}/Release/kernel"
)

# Definir diretório de saída
set_target_properties(${PROJECT_NAME}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
)

# Imprimir diretório de saída
message("Diretório de saída: ${CMAKE_BINARY_DIR}")
