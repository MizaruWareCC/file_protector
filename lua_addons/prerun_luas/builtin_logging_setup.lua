-- builtin_logging_setup.lua

-- This setup is used interface builtin_logging addon
-- It sets up CLI arguments for it

local ok, err

ok, err = CLIArgs.load_keyword_value("--logging_file") -- string: file to set output to, defaults to file_protector.log
if not ok then
    print("Failed to load keyword value --logging_file: " .. err)
end
ok, err = CLIArgs.load_keyword_value("--logging_action") -- string: can consist of [enc, dec] and sets wich actions do you want to log, if not set will log all actions
if not ok then
    print("Failed to load keyword value --logging_action: " .. err)
end