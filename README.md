## Usage
You can either run executable and get input window that will ask you to fill data, such as: action, file count, files, key
Or run it with command line:
```
--action encrypt --files file1 file2 file3 --folders folder1 "folder2/subfolder" [, --key "key", --recursive]
--action decrypt --files file1 file2 file3 --folders folder1 "folder2/subfolder" --key "key\" [, --recursive]
```

## Argument parser
This project uses custom parser, wich is minimal but doesn't support some features that you may expect it to.
```
--must_be_loaded_keyword ("any value" | value_without_space)
--any_flag
"--   flag   2" => can be used but not recomended, use alternatives when can for readability
--loaded_list value1 "value 2" "as much values as you want" [, --end]
```
Parser has types:
 - keyword with value
 - keyword with list
 - flag

First 2 must be loaded by either program itself or [lua addons](#lua-addons) or it will be handled as flag or will assume all of it are flags:
```
file_protector.exe --my_unloaded_keyword value // will be handled as flags: [--my_unloaded_keyword, value]
```
Keyword with list may end with either `--end` wich is reserved or with starting of other argument that must start with `--` wich you could have already seen at [usage example](#usage)

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

## Dependencies
Project uses [botan](https://github.com/randombit/botan) for cryptography and [Sol2](https://github.com/ThePhD/sol2) for lua embedding.
