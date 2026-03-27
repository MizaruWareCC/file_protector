Project uses c++23 as main language and Botan library as dependency for doing cryptographic actions.

You can either run executable and get input window that will ask you to fill data, such as: action, file count, files, key
Or run it with command line:
`--action encrypt --files file1 file2 file3 [, --key "key"]`
`--action decrypt --files file1 file2 file3 --key "key"`

Full action isn't checked, only its first character. If the first letter is e action will be chosen as encryption, d => decryption.

TODO:
    * Handle folders
    * Fix elapsed time counting user to input when encountering collision with file and asking if it should be overwritten
