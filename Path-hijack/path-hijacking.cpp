/*
Path hijacking PoC
author: Fir3n0x
description: Find writable path to hijack command execution by the system
g++ path-hijacking.cpp -o pathijack
*/

#include <vector>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>

using namespace std;
using namespace filesystem;

/* Verify if the directory is owned by root user */
bool isOwnedByRoot(const string& dir) {
    struct stat info;
    if (stat(dir.c_str(), &info) != 0) {
        return false;
    }
    return info.st_uid == 0;
}

/* Parse PATH variable to retrieve each path */
vector<string> getParsePaths() {
    vector<string> paths;

    const char* pathEnv = getenv("PATH");
    if (!pathEnv) {
        cerr << "Error : PATH not defined." << endl;
        return paths;
    }

    /* Create a long string to be parsed */
    string pathStr(pathEnv);
    /* Create a steam to browse the string */
    istringstream ss(pathStr);
    /* Create a token to store the path */
    string token;

    while (getline(ss, token, ':')) {
        paths.push_back(token);
    }
    
    return paths;    
}

/* Filter path's vector to get only paths with writable permission */
vector<string> getFilterPaths(const vector<string> paths) {
    vector<string> filterPaths;

    for(auto& path_from_vector : paths) {
        path dir_path = path_from_vector;
        if (exists(dir_path) && is_directory(dir_path)) {
            /* Get information about the current permission of the directory*/
            perms p = status(dir_path).permissions();

            /* Looking for the current writable permission of the directory */
            if ((p & perms::owner_write) != perms::none ||
                (p & perms::group_write) != perms::none ||
                (p & perms::others_write) != perms::none) {

                if (!isOwnedByRoot(path_from_vector)) {
                    filterPaths.push_back(path_from_vector);
                }
            }
        }
    }

    return filterPaths;
}

/* Main activity */
int main() {

    /* Get pathDirs */
    vector<string> pathDirs = getParsePaths();
    /* Filter vector variable */
    vector<string> filterPaths = getFilterPaths(pathDirs);

    cout << "Possible path hijack found (" << filterPaths.size() << "): " << endl;
    for (auto& dir : filterPaths) {
        cout << " - " << dir << endl;
    }

    return 0;
}