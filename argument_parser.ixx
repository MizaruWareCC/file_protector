export module argument_parser;

#include <vector>
#include <string>
#include <unordered_map>
#include <variant>
#include <stdexcept>

export class ArgParser {
public:
    ArgParser(int argc, const char* argv[]) : argc(argc), argv(argv) {}

    void load_keyword_value(std::string keyword) {
        if (!keyword.starts_with("--")) return;
        keywords_value.emplace(std::move(keyword), std::monostate{});
    }

    void load_keyword_list(std::string keyword) {
        if (!keyword.starts_with("--")) return;
        keywords_list.emplace(std::move(keyword), std::monostate{});
    }

    void process() {
        int i = 1; // skip path

        while (i < argc) {
            std::string arg = argv[i];

            if (keywords_value.contains(arg)) {
                if (i + 1 >= argc) {
                    throw std::out_of_range("missing value for keyword: " + arg);
                }

                loaded_kwv[arg] = argv[i + 1];
                i += 2;
                continue;
            }

            if (keywords_list.contains(arg)) {
                std::vector<std::string> items;
                ++i;

                while (i < argc) {
                    std::string next = argv[i];

                    if (next.starts_with("--")) {
                        break;
                    }

                    items.emplace_back(next);
                    ++i;
                }

                loaded_kwl[arg] = std::move(items);
                continue;
            }

            loaded_flags[arg] = std::monostate{};
            ++i;
        }
    }

    std::string get_value(const std::string& keyword) const {
        auto it = loaded_kwv.find(keyword);
        if (it == loaded_kwv.end()) {
            throw std::out_of_range("keyword not found: " + keyword);
        }
        return it->second;
    }

    std::vector<std::string> get_list(const std::string& keyword) const {
        auto it = loaded_kwl.find(keyword);
        if (it == loaded_kwl.end()) {
            throw std::out_of_range("keyword not found: " + keyword);
        }
        return it->second;
    }

    bool flag_set(const std::string& flag) const {
        return loaded_flags.contains(flag);
    }

    bool value_loaded(const std::string& keyword) const {
        return loaded_kwv.contains(keyword);
    }

    bool list_loaded(const std::string& keyword) const {
        return loaded_kwl.contains(keyword);
    }

private:
    int argc;
    const char** argv;

    std::unordered_map<std::string, std::monostate> keywords_value;
    std::unordered_map<std::string, std::monostate> keywords_list;

    std::unordered_map<std::string, std::string> loaded_kwv;
    std::unordered_map<std::string, std::vector<std::string>> loaded_kwl;
    std::unordered_map<std::string, std::monostate> loaded_flags;
};