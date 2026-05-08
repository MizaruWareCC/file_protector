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

#include <sol/sol.hpp>

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

enum Status { Success, Failure };

class LuaPath {
public:
    LuaPath() = default;
    LuaPath(const std::filesystem::path& path) : path(path) {}
    LuaPath(const std::string& path) : path(path) {}

    LuaPath root_name() const {
        return path.root_name();
    }

    LuaPath root_directory() const {
        return path.root_directory();
    }

    LuaPath root_path() const {
        return path.root_path();
    }

    LuaPath relative_path() const {
        return path.relative_path();
    }

    LuaPath parent_path() const {
        return path.parent_path();
    }

    LuaPath filename() const {
        return path.filename();
    }

    LuaPath stem() const {
        return path.stem();
    }

    LuaPath extension() const {
        return path.extension();
    }

    bool empty() const {
        return path.empty();
    }

    bool has_root_path() const {
        return path.has_root_path();
    }

    bool has_root_name() const {
        return path.has_root_name();
    }

    bool has_root_directory() const {
        return path.has_root_directory();
    }

    bool has_relative_path() const {
        return path.has_relative_path();
    }

    bool has_parent_path() const {
        return path.has_parent_path();
    }

    bool has_filename() const {
        return path.has_filename();
    }

    bool has_stem() const {
        return path.has_stem();
    }

    bool has_extension() const {
        return path.has_extension();
    }

    bool is_absolute() const {
        return path.is_absolute();
    }

    bool is_relative() const {
        return path.is_relative();
    }

    bool exists() const {
        return std::filesystem::exists(path);
    }

    bool is_file() const {
        return std::filesystem::is_regular_file(path);
    }

    std::string string() const {
        return path.string();
    }
private:
    std::filesystem::path path;
};

class EventManager {
public:
    using after_action_t = std::function<void(EventManager&, Action, Status, const LuaPath&, const LuaPath&)>;
    using preprocess_t = std::function<bool(EventManager&, Action, const LuaPath&, const LuaPath&)>;
    using before_exit_t = std::function<void(EventManager&, double, double, double)>;

    after_action_t after_action = [](EventManager&, Action, Status, const LuaPath&, const LuaPath&) {};
    preprocess_t on_preprocess = [](EventManager&, Action, const LuaPath&, const LuaPath&) { return true; };
    before_exit_t before_exit = [](EventManager&, double, double, double) {};

    void trigger_action(Action action, Status status, const LuaPath& file_path, const LuaPath& out_path) {
        after_action(*this, action, status, file_path, out_path);
    }

    bool trigger_preprocess(Action action, const LuaPath& file_path, const LuaPath& out_path) {
        return on_preprocess(*this, action, file_path, out_path);
    }

    void trigger_exit(double time_elapsed, double time_elapsed_io, double time_elapsed_cryptography) {
        before_exit(*this, time_elapsed, time_elapsed_io, time_elapsed_cryptography);
    }
};

class LuaArgs {
public:
    LuaArgs(ArgParser& args): parser(args) {}

    sol::object get_value(const std::string& keyword) const;

    sol::object get_list(const std::string& keyword) const;

    bool flag_set(const std::string& flag) const;

    bool value_loaded(const std::string& keyword) const;

    bool list_loaded(const std::string& keyword) const;
private:
    ArgParser& parser;
};

class LuaCrypt {
public:
    LuaCrypt(Action action) : action(action) {
        if (action == Enc)
            cipher = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        else
            cipher = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    }

    std::tuple<sol::object, sol::object> set_key(sol::this_state ts, std::string key) {
        sol::state_view lua = ts;
        if (key.size() == 32) {
            Botan::secure_vector<uint8_t> key_bytes(key.begin(), key.end());
            cipher->set_key(key_bytes);
            key_set = true;
            return std::tuple(sol::make_object(lua, true), sol::make_object(lua, key));
        }
        else if (key == "auto" && action == Enc) {
            this->key = random_key();
            Botan::secure_vector<uint8_t> key_bytes(this->key.begin(), this->key.end());
            cipher->set_key(key_bytes);
            key_set = true;
            return std::tuple(sol::make_object(lua, true), sol::make_object(lua, this->key));
        }

        return std::tuple(sol::make_object(lua, false), sol::make_object(lua, "invalid key"));
    }

    std::tuple<sol::object, sol::object> process(sol::this_state ts, std::string input) {
        sol::state_view lua = ts;

        if (!key_set) {
            return std::tuple(
                sol::make_object(lua, false),
                sol::make_object(lua, "no key")
            );
        }

        Botan::secure_vector<uint8_t> input_bytes(input.begin(), input.end());

        if (action == Enc) {
            const auto nonce = rng.random_vec<std::vector<uint8_t>>(cipher->default_nonce_length());

            try {
                cipher->start(nonce);
                cipher->finish(input_bytes);

                std::string out;
                out.reserve(nonce.size() + input_bytes.size());
                out.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
                out.append(reinterpret_cast<const char*>(input_bytes.data()), input_bytes.size());

                return std::tuple(
                    sol::make_object(lua, out),
                    sol::make_object(lua, sol::lua_nil)
                );
            }
            catch (const std::exception& e) {
                return std::tuple(
                    sol::make_object(lua, sol::lua_nil),
                    sol::make_object(lua, std::string(e.what()))
                );
            }
        }
        else {
            const size_t nonce_len = cipher->default_nonce_length();

            if (input_bytes.size() < nonce_len) {
                return std::tuple(
                    sol::make_object(lua, sol::lua_nil),
                    sol::make_object(lua, "invalid nonce")
                );
            }

            try {
                std::vector<uint8_t> nonce(input_bytes.begin(), input_bytes.begin() + nonce_len);
                Botan::secure_vector<uint8_t> payload(input_bytes.begin() + nonce_len, input_bytes.end());

                cipher->start(nonce);
                cipher->finish(payload);

                std::string out(reinterpret_cast<const char*>(payload.data()), payload.size());

                return std::tuple(
                    sol::make_object(lua, out),
                    sol::make_object(lua, sol::lua_nil)
                );
            }
            catch (const std::exception& e) {
                return std::tuple(
                    sol::make_object(lua, sol::lua_nil),
                    sol::make_object(lua, std::string(e.what()))
                );
            }
        }
    }

    std::string get_key() const {
        return key;
    }
private:
    bool key_set;
    Action action;
    std::unique_ptr<Botan::Cipher_Mode> cipher;
    Botan::AutoSeeded_RNG rng;
    std::string key;
};

void load_luas(sol::state& state, std::filesystem::path from) {
    for (auto entry : std::filesystem::directory_iterator(from)) {
        std::filesystem::path p = entry.path();
        if (entry.is_regular_file() && p.extension() == ".lua") {
            state.script_file(p.string());
            std::cout << "Loaded lua script: " << p.string() << "\n";
        }
    }
}

int main(int argc, const char* argv[]) {
    bool use_lua = false;
    sol::state lua_state;
    lua_state.open_libraries(
        sol::lib::base,  sol::lib::string,
        sol::lib::io,    sol::lib::os,
        sol::lib::bit32, sol::lib::coroutine,
        sol::lib::math,  sol::lib::table
    );

    lua_state.new_enum("Action",
        "Enc", Action::Enc,
        "Dec", Action::Dec
    );

    lua_state.new_enum("Status",
        "Success", Status::Success,
        "Failure", Status::Failure
    );

    lua_state.new_usertype<LuaPath>(
        "Path",
        sol::constructors<LuaPath(const std::string&)>(),
        "root_name", &LuaPath::root_name,
        "root_directory", &LuaPath::root_directory,
        "root_path", &LuaPath::root_path,
        "relative_path", &LuaPath::relative_path,
        "parent_path", &LuaPath::parent_path,
        "filename", &LuaPath::filename,
        "stem", &LuaPath::stem,
        "extension", &LuaPath::extension,
        "empty", &LuaPath::empty,
        "has_root_path", &LuaPath::has_root_path,
        "has_root_name", &LuaPath::has_root_name,
        "has_root_directory", &LuaPath::has_root_directory,
        "has_relative_path", &LuaPath::has_relative_path,
        "has_parent_path", &LuaPath::has_parent_path,
        "has_filename", &LuaPath::has_filename,
        "has_stem", &LuaPath::has_stem,
        "has_extension", &LuaPath::has_extension,
        "is_absolute", &LuaPath::is_absolute,
        "is_relative", &LuaPath::is_relative,
        "exists", &LuaPath::exists,
        "is_file", &LuaPath::is_file,
        "string", &LuaPath::string,
        sol::meta_function::to_string, &LuaPath::string
    );

    lua_state.new_usertype<LuaCrypt>(
        "LuaCrypt", sol::constructors<LuaCrypt(Action action)>(),
        "set_key", &LuaCrypt::set_key,
        "process", &LuaCrypt::process,
        "get_key", &LuaCrypt::get_key
    );

    std::vector<std::unique_ptr<EventManager>> lua_event_managers;

    lua_state.new_usertype<EventManager>(
        "EventManager",
        "new", sol::factories([&lua_event_managers]() {
            auto ptr = std::make_unique<EventManager>(EventManager());
            lua_event_managers.push_back(std::move(ptr));
            return lua_event_managers.back().get();
            }),
        "after_action", &EventManager::after_action,
        "on_preprocess", &EventManager::on_preprocess,
        "before_exit", &EventManager::before_exit
    );

    /*
        All lua callbacks:
         void on_action
            event.type := Action
            event.status := Enums.Status
            event.file_path := LuaPath
            event.out_file := LuaPath

        bool on_preprocess -> false => stop processing
            event.type := Action
            event.file_path := LuaPath
            event.out_file := LuaPath

         void before_exit
            event.time_elapsed := double
            event.time_elapsed_io := double
            event.time_elapsed_cryptography := double
    */

    auto lua_fs = lua_state.create_named_table("FileSystem");

    lua_fs.set_function("create_directory", [](const LuaPath& dir) {
        if (!dir.exists()) {
            std::filesystem::create_directory(dir.string());
        }
        });

    lua_fs.set_function("directory_iterator", [&lua_fs](const LuaPath& dir, bool recursive = false) {
        std::vector<LuaPath> items;

        if (recursive) {
            for (auto& entry : std::filesystem::recursive_directory_iterator(dir.string())) {
                items.emplace_back(entry.path());
            }
        }
        else {
            for (auto& entry : std::filesystem::directory_iterator(dir.string())) {
                items.emplace_back(entry.path());
            }
        }

        auto iter = [items = std::move(items), index = std::size_t{ 0 }]
        (sol::this_state ts, sol::object, sol::object) mutable -> sol::object {
            sol::state_view lua(ts);

            if (index >= items.size()) {
                return sol::make_object(lua, sol::lua_nil);
            }

            return sol::make_object(lua, items[index++]);
            };

        return std::make_tuple(
            sol::as_function(iter),
            sol::lua_nil,
            sol::lua_nil
        );
        });

    auto start_time_program = std::chrono::steady_clock::now();
    ArgParser args(argc, argv);

    auto lua_cli = lua_state.create_named_table("CLIArgs");

    lua_cli.set_function("load_keyword_value",[&args](const std::string& keyword) {
        args.load_keyword_value(keyword);
        });

    lua_cli.set_function("load_keyword_list", [&args](const std::string& keyword) {
            args.load_keyword_list(keyword);
        });

    args.load_keyword_value("--action");
    args.load_keyword_list("--files");
    args.load_keyword_list("--folders");
    args.load_keyword_value("--key");

    load_luas(lua_state, std::filesystem::current_path() / "lua_addons" / "prerun_luas");

    args.process();

    lua_cli.set_function("value_loaded", [&args](const std::string& keyword) {
        return args.value_loaded(keyword);
        });

    lua_cli.set_function("list_loaded", [&args](const std::string& keyword) {
        return args.list_loaded(keyword);
        });

    lua_cli.set_function("get_value", [&args](const sol::this_state ts, const std::string& keyword) {
        sol::state_view lua(ts);
        try {
            return sol::make_object(lua, args.get_value(keyword));
        }
        catch (const std::out_of_range&) { // not found
            return sol::make_object(lua, sol::nil);
        }
        });

    lua_cli.set_function("get_list", [&args](sol::this_state ts, const std::string& keyword) {
        sol::state_view lua(ts);
        try {
            return sol::make_object(lua, sol::as_table(args.get_list(keyword)));
        }
        catch (const std::out_of_range&) {
            return sol::make_object(lua, sol::nil);
        }
        });

    lua_cli.set_function("flag_set", [&args](const std::string& flag) {
        return args.flag_set(flag);
        });    

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
        std::cout << "Use luas(Y/N): ";
        std::string use_lua_t;
        std::cin >> use_lua_t;
        if (use_lua_t == "Y" || use_lua_t == "y") {
            use_lua = true;
            load_luas(lua_state, std::filesystem::current_path() / "lua_addons");
        }

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

            if (args.flag_set("--lua")) {
                std::cout << "Use lua flag selected, loading luas...\n";
                use_lua = true;
                load_luas(lua_state, std::filesystem::current_path() / "lua_addons");
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
            if (use_lua) {
                for (auto& mngr : lua_event_managers) {
                    if (!mngr->trigger_preprocess(action, file, out_file)) {
                        std::cout << "Ignoring file " << file << " because lua prohibited it\n";
                        return false;
                    }
                }
            }
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
                    if (use_lua) {
                        for (auto& mngr : lua_event_managers) {
                            mngr->trigger_action(action, Status::Success, input_file, output_file);
                        }
                    }
                    std::cout << "Ended decryption for current file successfully.\n";
                }
                else if (use_lua) {
                    for (auto& mngr : lua_event_managers) {
                        mngr->trigger_action(action, Status::Failure, input_file, output_file);
                    }
                }
            }
            else {
                std::cout << "Encrypting file \"" << input_file.string() << "\"\n";

                if (encrypt_file(input_file, output_file, *enc_cipher, rng, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                    ++successful_operation_count;
                    if (use_lua) {
                        for (auto& mngr : lua_event_managers) {
                            mngr->trigger_action(action, Status::Success, input_file, output_file);
                        }
                    }
                    std::cout << "Ended encryption for current file successfully.\n";
                }
                else if (use_lua) {
                    for (auto& mngr : lua_event_managers) {
                        mngr->trigger_action(action, Status::Failure, input_file, output_file);
                    }
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
                            if (use_lua) {
                                for (auto& mngr : lua_event_managers) {
                                    mngr->trigger_action(action, Status::Success, input_file, output_file);
                                }
                            }
                            std::cout << "Ended decryption for current file successfully.\n";
                        }
                        else if (use_lua) {
                            for (auto& mngr : lua_event_managers) {
                                mngr->trigger_action(action, Status::Failure, input_file, output_file);
                            }
                        }
                    }
                    else {
                        std::cout << "Encrypting file \"" << input_file.string() << "\"\n";

                        if (encrypt_file(input_file, output_file, *enc_cipher, rng, &elapsed_ms_cryptography, &elapsed_ms_io)) {
                            ++successful_operation_count;
                            if (use_lua) {
                                for (auto& mngr : lua_event_managers) {
                                    mngr->trigger_action(action, Status::Success, input_file, output_file);
                                }
                            }
                            std::cout << "Ended encryption for current file successfully.\n";
                        }
                        else if (use_lua) {
                            for (auto& mngr : lua_event_managers) {
                                mngr->trigger_action(action, Status::Failure, input_file, output_file);
                            }
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
    if (use_lua) {
        for (auto& mngr : lua_event_managers) {
            mngr->trigger_exit(elapsed_ms_program.count(), elapsed_ms_io, elapsed_ms_cryptography);
        }
    }
    std::cout << "Enter any key to continiue...";
    auto _ = _getch();

    return 0;
}