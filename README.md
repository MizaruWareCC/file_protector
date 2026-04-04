Project uses c++23 as main language and Botan library as dependency for doing cryptographic actions.

## Usage
You can either run executable and get input window that will ask you to fill data, such as: action, file count, files, key
Or run it with command line:
```
--action encrypt --files file1 file2 file3 --folders folder1 "folder2/subfolder" [, --key "key", --recursive]
--action decrypt --files file1 file2 file3 --folders folder1 "folder2/subfolder" --key "key\" [, --recursive]
```

## Lua addons
Flag `--lua` will make program to use external lua addons. Basic addons, like logging are already implemented and can be found [here](https://github.com/MizaruWareCC/file_protector/tree/main/lua_addons)
All addons must be located at `lua_addons` folder in the same directory as your executable.
`lua_addons` also has sub-directory called `prerun_luas` wich contains lua scripts that are used to setup main script, for example setting up argument for a parser:
```lua
CLIArgs.load_keyword_value("--logging_file")
CLIArgs.load_keyword_value("--logging_action")
```

## Making addons
There's no documentation at the moment, it will be released later on.
Right now you will have to look inside source code for API.
For example code below will make read-only enum wich can be indexed as Action.Enc
```c++
lua_state.new_enum("Action",
    "Enc", Action::Enc,
    "Dec", Action::Dec
);
```
Or as example below, will make usertype object wich will act like lua table and can be used like `local path = LuaPath.new("C:\\")` and then use its methods with `path:root_name()`
```c++
lua_state.new_usertype<LuaPath>(
    "Path",
    sol::constructors<LuaPath(const std::string&)>(),
    "root_name", &LuaPath::root_name,
    ...
```
