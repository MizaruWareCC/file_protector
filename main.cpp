#include <iostream>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <chrono>
#include <vector>
#include <cstring>
#include <conio.h>
#include <random>

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

import argument_parser;

std::string random_key() {
    const int start_ascii = 33;
    const int end_ascii = 125;

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<size_t> distribution(start_ascii, end_ascii);

    std::string key;
    key.reserve(32);

    for (int i = 0; i < 32; i++) {
        key += distribution(generator);
    }
    return key;
}

enum Action {
    Enc, Dec
};

enum Mode {
    Override, KeepFiles, Ask
};

std::vector<uint8_t> file_to_vec(std::ifstream& file) {
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

bool exists_and_file(const std::filesystem::path& file) {
    return std::filesystem::exists(file) && std::filesystem::is_regular_file(file);
}

int main(int argc, const char* argv[])
{
    ArgParser args(argc, argv);
    args.load_keyword_value("--action");
    args.load_keyword_list("--files");
    args.load_keyword_value("--key");
    args.process();

    Action action = Action::Enc;
    std::vector<std::filesystem::path> paths;
    std::string key_t;

    auto validate_key = [&](std::string& key) -> bool {
        if (key == "auto" && action == Action::Enc) {
            key = random_key();
            std::cout << "Generated key: " << key << '\n';
            return true;
        }

        if (key.size() != 32) {
            std::cout << "Key size must be exactly 32 bytes for AES-256.\n";
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

        std::cout << "Enter file count: ";
        std::string num;
        std::cin >> num;
        int count = std::stoi(num);

        if (count < 1) {
            return 0;
        }

        for (int i = 1; i <= count; i++) {
            std::cout << "File path " << i << ": ";
            std::string tmp;
            std::cin >> tmp;
            paths.emplace_back(tmp);
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

            if (!args.value_loaded("--key")) {
                if (action == Action::Enc) key_value = "auto";
                else {
                    std::cout << "--key is required for decryption\n";
                    return 1;
                }
            }
            else {
                key_value = args.get_value("--key");
            }

            std::vector<std::string> file_list = args.get_list("--files");

            if (action_t.starts_with("d")) {
                action = Action::Dec;
            }
            else if (!action_t.starts_with("e")) {
                std::cout << "Unknown action: " << action_t << "\n";
                std::cout << "Enter any key to continiue...";
                auto _ = _getch();
                return 1;
            }

            for (const std::string& f : file_list) {
                paths.emplace_back(f);
            }

            key_t = std::move(key_value);

            if (!validate_key(key_t)) {
                return 1;
            }
        }
        catch (const std::out_of_range&) {
            std::cout << "Missing required arguments.\n";
            std::cout << "Usage:\n";
            std::cout << "  --action encrypt --files file1 file2 file3 [, --key \"key\"]\n";
            std::cout << "  --action decrypt --files file1 file2 file3 --key \"key\"\n";
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

    int successful_operation_count = 0;

    auto start = std::chrono::steady_clock::now();

    if (action == Action::Enc) {
        Botan::AutoSeeded_RNG rng;
        const auto cipher = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        cipher->set_key(key);
        for (const std::filesystem::path& file : paths) {
            std::filesystem::path out_file = base_folder / file.filename();

            if (mode == Mode::Ask && exists_and_file(out_file)) {
                std::cout << "Collision for file " << file.string() << ", overwrite(Y/N): ";
                std::string choice;
                std::cin >> choice;
                if (choice != "Y" && choice != "y") {
                    continue;
                }
            }
            else if (mode == Mode::KeepFiles && exists_and_file(out_file)) {
                std::cout << "Collision for file " << file.string() << ", skipping...\n";
                continue;
            }

            std::cout << "Encrypting file \"" << file.string() << "\"\n";

            std::ifstream in_stream(file, std::ios::binary);
            if (!in_stream.is_open()) {
                std::cout << "Failed opening file with path \"" << file.string() << "\"\n";
                continue;
            }

            std::vector<uint8_t> plain_vec = file_to_vec(in_stream);
            Botan::secure_vector<uint8_t> buffer(plain_vec.begin(), plain_vec.end());

            const auto nonce = rng.random_vec<std::vector<uint8_t>>(cipher->default_nonce_length());

            cipher->start(nonce);
            cipher->finish(buffer);

            std::ofstream out_stream(out_file, std::ios::binary);
            if (!out_stream.is_open()) {
                std::cout << "Failed opening file with path \"" << out_file.string() << "\"\n";
                continue;
            }

            // [nonce][ciphertext+tag]
            out_stream.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
            out_stream.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

            ++successful_operation_count;
            std::cout << "Ended encryption for current file successfully.\n";
        }
    }
    else {
        const auto cipher = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        cipher->set_key(key);
        for (const std::filesystem::path& file : paths) {
            std::filesystem::path out_file = base_folder / file.filename();

            if (mode == Mode::Ask && exists_and_file(out_file)) {
                std::cout << "Collision for file " << file.string() << ", overwrite(Y/N): ";
                std::string choice;
                std::cin >> choice;
                if (choice != "Y" && choice != "y") {
                    continue;
                }
            }
            else if (mode == Mode::KeepFiles && exists_and_file(out_file)) {
                std::cout << "Collision for file " << file.string() << ", skipping...\n";
                continue;
            }

            std::ifstream in_stream(file, std::ios::binary);
            if (!in_stream.is_open()) {
                std::cout << "Failed opening file with path \"" << file.string() << "\"\n";
                continue;
            }

            std::vector<uint8_t> nonce(cipher->default_nonce_length());

            in_stream.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
            if (static_cast<size_t>(in_stream.gcount()) != nonce.size()) {
                std::cout << "File too short: missing nonce\n";
                continue;
            }

            std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in_stream)),
                std::istreambuf_iterator<char>()); // ciphertext + tag

            try {
                cipher->start(nonce);
                Botan::secure_vector<uint8_t> plaintext(buffer.begin(), buffer.end());
                cipher->finish(plaintext);

                std::ofstream out_stream(out_file, std::ios::binary);
                if (!out_stream.is_open()) {
                    std::cout << "Failed opening file with path \"" << out_file.string() << "\"\n";
                    continue;
                }

                out_stream.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
                ++successful_operation_count;
            }
            catch (const Botan::Invalid_Authentication_Tag&) {
                std::cout << "Authentication failed for file " << file.string() << "\n";
                continue;
            }

        }
    }

    auto end = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::string action_t = (action == Action::Enc) ? "encrypted" : "decrypted";

    std::cout << "[Statistic for " << action_t << "]\n"
        << " Files " << action_t << ": " << successful_operation_count << " / " << paths.size() << " ("
        << (paths.empty() ? 0.0 : (double)successful_operation_count * 100.0 / (double)paths.size()) << "%)\n"
        << " Time elapsed: " << elapsed_ms << " ms\n"
        << " Output folder: " << base_folder_t << '\n';

    std::cout << "Enter any key to continiue...";

    auto _ = _getch();

    return 0;
}

/*
TODO:
    Better command line argument handling
    Handle folders
    Fix elapsed time counting user to input when encountering collision with file and asking if it should be overwritten with Action::Ask set
*/