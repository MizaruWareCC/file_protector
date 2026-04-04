-- builtin_blacklist.lua

-- Must have builtin_blacklist_setup

if CLIArgs.flag_set("--blacklist") then
    print("Loading blacklist")
    local blacklisted_files = CLIArgs.get_list("--blacklisted_files") or {}
    local blacklisted_exts = CLIArgs.get_list("--blacklisted_exts") or {}
    local blacklisted_regex = CLIArgs.get_list("--blacklisted_regex") or {}
    print("Loaded blacklist settings")

    local tmp = {}
    for _, v in ipairs(blacklisted_regex) do -- validate regex
        local ok, res = pcall(string.find, "", v)
        if ok then
            table.insert(tmp, v)
        else
            print("Invalid regex(ignored): " .. v)
        end
    end
    blacklisted_regex = tmp
    tmp = nil

    if #blacklisted_exts ~= 0 and blacklisted_files ~= 0 and blacklisted_regex ~= 0 then -- dont register event if there is no filters
        local event_manager = EventManager.new()

        function event_manager:on_preprocess(action, in_file_path, out_file_path)
            for _, file in ipairs(blacklisted_files) do
                if file == in_file_path:filename():string() then
                    return false
                end
            end

            for _, ext in ipairs(blacklisted_exts) do
                if ext == in_file_path:extension():string() then
                    return false
                end
            end

            for _, reg in ipairs(blacklisted_regex) do
                if in_file_path:filename():string():find(reg) then
                    return false
                end
            end

            return true
        end

        RegisterEventManager(event_manager)
        print("Blacklist is initialized")
    end
end
