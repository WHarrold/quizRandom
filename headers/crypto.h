//Purpose: This file contains all cryptographic and password functions

#pragma once

#include <string>

std::string create_hash (const std::string &input);

bool create_password (std::string password, const std::string &username, const std::string &database);

bool check_password (std::string password, const std::string &username, const std::string &database);

bool change_password (std::string password, const std::string &username, const std::string &database);

std::string create_salt();

