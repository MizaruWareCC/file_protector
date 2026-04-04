export module argument_parser;

#include <vector>
#include <string>
#include <unordered_map>
#include <variant>
#include <stdexcept>

export class ArgParser {
public:
    static constexpr const char* list_end = "--end";

    ArgParser(int argc, const char* argv[]) : argc(argc), argv(argv) {}

    void load_keyword_value(std::string keyword) {
        if (!is_valid_keyword(keyword)) return;
        if (keyword == list_end) return;
        keywords_value.emplace(std::move(keyword), std::monostate{});
    }

    void load_keyword_list(std::string keyword) {
        if (!is_valid_keyword(keyword)) return;
        if (keyword == list_end) return;
        keywords_list.emplace(std::move(keyword), std::monostate{});
    }

    void process() {
        int i = 1; // skip program path

        while (i < argc) {
            std::string arg = argv[i];

            if (arg == list_end) {
                throw std::runtime_error("unexpected reserved token: --end");
            }

            if (keywords_value.contains(arg)) {
                if (i + 1 >= argc) {
                    throw std::out_of_range("missing value for keyword: " + arg);
                }

                std::string value = argv[i + 1];
                if (value == list_end) {
                    throw std::out_of_range("missing value for keyword: " + arg);
                }

                loaded_kwv[arg] = std::move(value);
                i += 2;
                continue;
            }

            if (keywords_list.contains(arg)) {
                std::vector<std::string> items;
                ++i;

                while (i < argc) {
                    std::string next = argv[i];

                    if (next == list_end || next.starts_with("--")) { // allow both --end or next flag or keyword
                        ++i;
                        break;
                    }

                    items.emplace_back(std::move(next));
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
    static bool is_valid_keyword(const std::string& keyword) {
        return keyword.starts_with("--");
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