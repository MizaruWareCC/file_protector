#include <iostream>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <chrono>
#include <vector>
#include <cstring>
#include <conio.h>
#include <random>
#include <memory>

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

import argument_parser;

std::vector<uint8_t> file_to_vec(std::ifstream& file) {
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
}

std::string random_key() {
    const int start_ascii = 65;
    const int end_ascii = 122;

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(start_ascii, end_ascii);

    std::string key;
    key.reserve(32);

    for (int i = 0; i < 32; i++) {
        key += static_cast<char>(distribution(generator));
    }
    return key;
}

bool exists_and_file(const std::filesystem::path& file) {
    return std::filesystem::exists(file) && std::filesystem::is_regular_file(file);
}

bool encrypt_file(const std::filesystem::path& input_file, const std::filesystem::path& output_file,
                  Botan::Cipher_Mode& cipher, Botan::AutoSeeded_RNG& rng,
                  double* time_spent_in_ms_cryptography, double* time_spent_in_ms_io) {
    std::ifstream in_stream(input_file, std::ios::binary);
    if (!in_stream.is_open()) {
        std::cout << "Failed opening file with path \"" << input_file.string() << "\"\n";
        return false;
    }

    std::vector<uint8_t> plain_vec = file_to_vec(in_stream);
    Botan::secure_vector<uint8_t> buffer(plain_vec.begin(), plain_vec.end());

    const auto nonce = rng.random_vec<std::vector<uint8_t>>(cipher.default_nonce_length());


    try {
        auto start = std::chrono::steady_clock::now();
        cipher.start(nonce);
        cipher.finish(buffer);
        if (time_spent_in_ms_cryptography != nullptr) {
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::milli> ms = end - start;
            *time_spent_in_ms_cryptography += ms.count();
        }

        start = std::chrono::steady_clock::now();
        std::ofstream out_stream(output_file, std::ios::binary);
        if (!out_stream.is_open()) {
            std::cout << "Failed opening file with path \"" << output_file.string() << "\"\n";
            return false;
        }

        // [nonce][ciphertext+tag]
        out_stream.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
        out_stream.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        if (time_spent_in_ms_io != nullptr) {
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::milli> ms = end - start;
            *time_spent_in_ms_io += ms.count();
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cout << "Encryption failed for file \"" << input_file.string() << "\": " << e.what() << "\n";
        return false;
    }
}

bool decrypt_file(const std::filesystem::path& input_file, const std::filesystem::path& output_file,
                  Botan::Cipher_Mode& cipher, double* time_spent_in_ms_cryptography, double* time_spent_in_ms_io) {
    std::ifstream in_stream(input_file, std::ios::binary);
    if (!in_stream.is_open()) {
        std::cout << "Failed opening file with path \"" << input_file.string() << "\"\n";
        return false;
    }

    const size_t nonce_len = cipher.default_nonce_length();
    std::vector<uint8_t> nonce(nonce_len);

    in_stream.read(reinterpret_cast<char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
    if (static_cast<size_t>(in_stream.gcount()) != nonce.size()) {
        std::cout << "File too short: missing nonce\n";
        return false;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in_stream)),
        std::istreambuf_iterator<char>());

    try {
        auto start = std::chrono::steady_clock::now();
        cipher.start(nonce);
        Botan::secure_vector<uint8_t> plaintext(buffer.begin(), buffer.end());
        cipher.finish(plaintext);
        if (time_spent_in_ms_cryptography != nullptr) {
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::milli> ms = end - start;
            *time_spent_in_ms_cryptography += ms.count();
        }

        start = std::chrono::steady_clock::now();
        std::ofstream out_stream(output_file, std::ios::binary);
        if (!out_stream.is_open()) {
            std::cout << "Failed opening file with path \"" << output_file.string() << "\"\n";
            return false;
        }

        out_stream.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        if (time_spent_in_ms_io != nullptr) {
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::milli> ms = end - start;
            *time_spent_in_ms_io += ms.count();
        }
        return true;
    }
    catch (const Botan::Invalid_Authentication_Tag&) {
        std::cout << "Authentication failed for file \"" << input_file.string() << "\"\n";
        return false;
    }
    catch (const std::exception& e) {
        std::cout << "Decryption failed for file \"" << input_file.string() << "\": " << e.what() << "\n";
        return false;
    }
}

enum Action {
    Enc, Dec
};

enum Mode {
    Override, KeepFiles, Ask
};

int main(int argc, const char* argv[])
{
    auto start_time_program = std::chrono::steady_clock::now();
    ArgParser args(argc, argv);
    args.load_keyword_value("--action");
    args.load_keyword_list("--files");
    args.load_keyword_list("--folders");
    args.load_keyword_value("--key");
    args.process();

    Action action = Action::Enc;
    std::vector<std::filesystem::path> files_path;
    std::vector<std::filesystem::path> folders_path;
    std::string key_t;

    auto validate_key = [&](std::string& key) -> bool {
        if (key == "auto" && action == Action::Enc) {
            key = random_key();
            std::cout << "Generated key: " << key << '\n';
            return true;
        }

        if (key.size() != 32) {
            std::cout << "Key size must be exactly 32 bytes for AES-256. Your key size: " << key.size() << ", key: \"" << key << "\"\n";
            std::cout << "Enter any key to continiue...";
            auto _ = _getch();
            return false;
        }

        return true;
        };

    if (argc == 1) {
        std::cout << "Enter action(encrypt/decrypt): ";
        std::string choice;
        std::cin >> choice;

        if (choice.starts_with("d")) {
            action = Action::Dec;
        }
        else if (!choice.starts_with("e")) {
            std::cout << "It must be either encrypt or decrypt\n";
            std::cout << "Enter any key to continiue...";
            auto _ = _getch();
            return 1;
        }

        std::cout << "Enter files count: ";
        std::string files_count_t;
        std::cin >> files_count_t;
        int files_count = std::stoi(files_count_t);

        for (int i = 1; i <= files_count; i++) {
            std::cout << "File path " << i << ": ";
            std::string tmp;
            std::cin >> tmp;
            files_path.emplace_back(tmp);
        }

        std::cout << "Enter folders count: ";
        std::string folders_count_t;
        std::cin >> folders_count_t;
        int folders_count = std::stoi(folders_count_t);

        for (int i = 1; i <= folders_count; i++) {
            std::cout << "Folder path " << i << ": ";
            std::string tmp;
            std::cin >> tmp;
            folders_path.emplace_back(tmp);
        }

        if (folders_count == 0 && files_count == 0) {
            std::cout << "Enter any key to continiue...";
            auto _ = _getch();
            return 0;
        }

        std::cout << "Enter key: ";
        std::cin >> key_t;

        if (!validate_key(key_t)) {
            return 1;
        }
    }
    else {
        try {
            std::string action_t = args.get_value("--action");
            std::string key_value;

            if (action_t.starts_with("d")) {
                action = Action::Dec;
            }
            else if (!action_t.starts_with("e")) {
                std::cout << "Unknown action: " << action_t << "\n";
                std::cout << "Enter any key to continiue...";
                auto _ = _getch();
                return 1;
            }

            if (!args.value_loaded("--key")) {
                if (action == Action::Enc) key_value = "auto";
                else {
                    std::cout << "--key is required for decryption\n";
                    std::cout << "Enter any key to continiue...";
                    auto _ = _getch();
                    return 1;
                }
            }
            else {
                key_value = args.get_value("--key");
            }

            if (args.list_loaded("--files")) {
                std::vector<std::string> files_list = args.get_list("--files");
                for (const std::string& f : files_list) {
                    files_path.emplace_back(f);
                }
            }

            if (args.list_loaded("--folders")) {
                std::vector<std::string> folders_list = args.get_list("--folders");
                for (const std::string& f : folders_list) {
                    folders_path.emplace_back(f);
                }
            }

            if (folders_path.size() == 0 && files_path.size() == 0) {
                throw std::out_of_range{"at least 1 file or 1 folder must be specified"};
            }

            key_t = std::move(key_value);

            if (!validate_key(key_t)) {
                return 1;
            }
        }
        catch (const std::out_of_range&) {
            std::cout << "Missing required arguments.\n";
            std::cout << "Usage:\n";
            std::cout << "  --action encrypt --files file1 file2 file3 --folders folder1 \"folder2/subfolder\" [, --key \"key\", --recursive]\n";
            std::cout << "  --action decrypt --files file1 file2 file3 --folders folder1 \"folder2/subfolder\" --key \"key\" [, --recursive]\n";
            std::cout << "Enter any key to continiue...";
            auto _ = _getch();
            return 1;
        }
    }

    std::vector<uint8_t> key(key_t.begin(), key_t.end());

    Mode mode = Mode::Override;
    std::string base_folder_t = action == Action::Enc ? "encrypt" : "decrypt";

    if (std::filesystem::exists(base_folder_t) &&
        std::filesystem::is_directory(base_folder_t) &&
        !std::filesystem::is_empty(base_folder_t)) {
        std::string choice;
        while (true) {
            std::cout
                << "You have folder \"" << base_folder_t << "\", running program can override files on collision, select action:"
                << "\n 1 - Change save folder"
                << "\n 2 - Proceed and override on collision"
                << "\n 3 - Proceed and dont override collisions"
                << "\n 4 - Proceed and ask action on collision"
                << "\n 0 - Exit"
                << "\nEnter your choice: ";
            std::cin >> choice;

            if (choice == "0") {
                return 0;
            }
            else if (choice == "1") {
                std::cout << "\nEnter new directory: ";
                std::cin >> base_folder_t;
                break;
            }
            else if (choice == "2") {
                mode = Mode::Override;
                break;
            }
            else if (choice == "3") {
                mode = Mode::KeepFiles;
                break;
            }
            else if (choice == "4") {
                mode = Mode::Ask;
                break;
            }
            std::cout << "Unknown choice \"" << choice << "\"\n";
        }
    }

    if (!(std::filesystem::exists(base_folder_t) && std::filesystem::is_directory(base_folder_t))) {
        std::filesystem::create_directory(base_folder_t);
    }

    std::filesystem::path base_folder = base_folder_t;

    int total_files_count = 0;
    int successful_operation_count = 0;

    double elapsed_ms_cryptography = 0;
    double elapsed_ms_io = 0;

    Botan::AutoSeeded_RNG rng;
    auto enc_cipher = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    auto dec_cipher = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);

    enc_cipher->set_key(key);
    dec_cipher->set_key(key);

    auto before_action = [&](std::filesystem::path file, std::filesystem::path out_file) {
            if (mode == Mode::Ask && exists_and_file(out_file)) {
                std::cout << "Collision for file \"" << file.string() << "\", overwrite(Y/N): ";
                std::string choice;
                std::cin >> choice;
                if (choice != "Y" && choice != "y") {
                    return false;
                }
            }
            else if (mode == Mode::KeepFiles && exists_and_file(out_file)) {
                std::cout << "Collision for file \"" << file.string() << "\", skipping...\n";
                return false;
            }
            return true;
        };

    
    for (const std::filesystem::path& input_file : files_path) {
        ++total_files_count;
        std::filesystem::path output_file = base_folder / input_file.filename();

        if (before_action(input_file, output_file)) {
            if (action == Action::Dec) {
                std::cout << "Decrypting file \"" << input_file.string() << "\"\n";

                if (decrypt_file(input_file, output_file, *dec_cipher, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                    ++successful_operation_count;
                    std::cout << "Ended decryption for current file successfully.\n";
                }
            }
            else {
                std::cout << "Encrypting file \"" << input_file.string() << "\"\n";

                if (encrypt_file(input_file, output_file, *enc_cipher, rng, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                    ++successful_operation_count;
                    std::cout << "Ended encryption for current file successfully.\n";
                }
            }
        }            
    }
    if (args.flag_set("--recursive")) {
        for (const std::filesystem::path& folder : folders_path) {
            std::filesystem::path output_root = base_folder / folder.filename();
            for (const auto& entry : std::filesystem::recursive_directory_iterator(folder)) {
                if (!entry.is_regular_file()) {
                    continue;
                }

                ++total_files_count;

                const std::filesystem::path input_file = entry.path();

                const std::filesystem::path rel = std::filesystem::relative(input_file, folder);

                const std::filesystem::path output_file = output_root / rel;

                std::filesystem::create_directories(output_file.parent_path());

                if (before_action(input_file, output_file)) {
                    if (action == Action::Dec) {
                        std::cout << "Decrypting file \"" << input_file.string() << "\"\n";

                        if (decrypt_file(input_file, output_file, *dec_cipher, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                            ++successful_operation_count;
                            std::cout << "Ended decryption for current file successfully.\n";
                        }
                    }
                    else {
                        std::cout << "Encrypting file \"" << input_file.string() << "\"\n";

                        if (encrypt_file(input_file, output_file, *enc_cipher, rng, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                            ++successful_operation_count;
                            std::cout << "Ended encryption for current file successfully.\n";
                        }
                    }
                }
            }
        }
    }
    else {
        for (const std::filesystem::path& folder : folders_path) {
            std::filesystem::path output_directory = base_folder / folder.filename();
            std::filesystem::create_directories(output_directory);

            for (const auto& entry : std::filesystem::directory_iterator{ folder }) {
                if (!entry.is_regular_file()) {
                    continue;
                }

                ++total_files_count;

                std::filesystem::path input_file = entry.path();
                std::filesystem::path output_file = output_directory / input_file.filename();

                std::filesystem::create_directories(output_file.parent_path());

                if (before_action(input_file, output_file)) {
                    if (action == Action::Dec) {
                        std::cout << "Decrypting file \"" << input_file.string() << "\"\n";

                        if (decrypt_file(input_file, output_file, *dec_cipher, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                            ++successful_operation_count;
                            std::cout << "Ended decryption for current file successfully.\n";
                        }
                    }
                    else {
                        std::cout << "Encrypting file \"" << input_file.string() << "\"\n";

                        if (encrypt_file(input_file, output_file, *enc_cipher, rng, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                            ++successful_operation_count;
                            std::cout << "Ended encryption for current file successfully.\n";
                        }
                    }
                }
            }
        }
    }


    std::string action_t = (action == Action::Enc) ? "encrypted" : "decrypted";

    std::cout << "[Statistic for " << action_t << "]\n"
        << " Files " << action_t << ": " << successful_operation_count << " / " << total_files_count << " ("
        << (double)successful_operation_count * 100.0 / (double)total_files_count << "%)\n"
        << " Time elapsed for crypotgraphy: " << elapsed_ms_cryptography << " ms\n"
        << " Time elapsed for io: " << elapsed_ms_io << " ms (doesn't include folders actions)\n"
        << " Output folder: " << base_folder_t << '\n';

    auto end_time_program = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::milli> elapsed_ms_program = end_time_program - start_time_program;

    std::cout << "Program was running for " << elapsed_ms_program.count() << "ms (~" << elapsed_ms_program.count() / 1000.0 << "sec)\n";
    std::cout << "Enter any key to continiue...";
    auto _ = _getch();

    return 0;
}