-- builtin_logging_setup.lua

-- This setup is used interface builtin_logging addon
-- It sets up CLI arguments for it


CLIArgs.load_keyword_value("--logging_file") -- string: file to set output to, defaults to file_protector.log
CLIArgs.load_keyword_value("--logging_action") -- string: can consist of [enc, dec] and sets wich actions do you want to log, if not set will log all actions