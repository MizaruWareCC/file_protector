-- builtin_logging.lua

-- Must have builtin_logging_setup

if CLIArgs.flag_set("--logging") then
    print("Logging enabled")
    local output_file = CLIArgs.get_value("--logging_file") or "file_protector.log"
    print("Loaded output file: " .. output_file)

    print("Loaded action settings")

    local log_file, err = io.open(output_file, "w")

    if log_file then
        print("Opened file")
        local event_manager = EventManager.new()

        function event_manager:on_preprocess(action, in_file_path, out_file_path)
            log_file:write(
                "[" .. tostring(os.date()) .. "] Preprocess action: " .. (action == Action.Enc and "encryption" or "decryption") .. "; input file: "
                .. in_file_path:string() .. "; out file: " .. out_file_path:string() .. "\n"
            )
            return true -- dont forget to allow action
        end

        function event_manager:after_action(action, status, in_file_path, out_file_path)
            log_file:write(
                "[" .. tostring(os.date()) .. "] Action: " .. (action == Action.Enc and "encryption" or "decryption") .. "; input file: "
                .. in_file_path:string() .. "; out file: " .. out_file_path:string() .. "; Result: " .. (status == Status.Success and "success" or "Failure") .. "\n"
            )
        end

        function event_manager:before_exit(complete_time, io_time, crypt_time)
            log_file:write(
                "[" .. tostring(os.date()) .. "] Exit, time spent: " .. tostring(complete_time) .. "ms; on io: " .. tostring(io_time) .. "ms; on cryptography: " .. tostring(crypt_time) .. "ms"
            )
            log_file:close()
        end

        RegisterEventManager(event_manager)
        print("Logger is initalized")
    else
        print("Couldn't open log file. Error " .. tostring(err))
    end
end