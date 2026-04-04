-- builtin_blacklist_setup.lua

-- Setup for builtin_blacklist

CLIArgs.load_keyword_list("--blacklisted_files")   -- list of blacklisted files
CLIArgs.load_keyword_list("--blacklisted_exts")    -- list of blacklisted extensions
CLIArgs.load_keyword_list("--blacklisted_regex")   -- list of blacklisted regex, checked on filename