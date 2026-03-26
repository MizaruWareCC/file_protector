Project uses c++23 as main language and Botan library as dependency for doing cryptographic actions.

You can either run executable and get input window that will ask you to fill data, such as: action, file count, files, key
Or run it with command line `[file].[exe] (en | de)crypt file, [file2, file3, ...], key (auto can be used for encryption to generate key)`

Full action isn't checked, only its first character, so `edecrypt` will stand for encrypt, same goes other way.

TODO:
    * Better command line argument handling
    * Handle folders
    * Fix elapsed time counting user to input when encountering collision with file and asking if it should be overwritten with Action::Ask set
