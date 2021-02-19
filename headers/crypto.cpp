//implmentqtion file for crypto.h
#include<iostream>
#include<iomanip>
#include<cstdio>
#include<sstream>
#include<string>
#include<cstring>
#include<random>
#include"crypto.h"
#include <openssl/evp.h>
#include "openssl/sha.h"
#include"sqlite3.h"

//thus functiin takes a string, which will be a password but could be used to hash any string, it using the sha512 algorithm
std::string create_hash(const std::string &input)
{
  unsigned char hash[SHA512_DIGEST_LENGTH];
  SHA512_CTX sha256;
  SHA512_Init(&sha256);
  SHA512_Update(&sha256, input.c_str(), input.size());
  SHA512_Final(hash, &sha256);
  std::stringstream ss;
  for(int i = 0; i < SHA512_DIGEST_LENGTH; ++i)
  {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }
  return ss.str();
}



//this function chects to see of a username is already being used
bool check_username (const std::string &username, const std::string &database) {
	sqlite3 *pDB;
	int rc= sqlite3_open(database.c_str(),&pDB);
	if (rc != SQLITE_OK){
		std::cout << "bad database: " << database << std::endl;
		return false;
	}
	
	std::string sql= "SELECT COUNT(*) FROM USERS WHERE USERNAME = ?;";
	sqlite3_stmt *pStmt = nullptr;
 if (SQLITE_OK != (rc=sqlite3_prepare_v2(pDB,sql.c_str(),sql.size(),&pStmt,nullptr)))
  {
    std::cout << "Failed to prepare count: " << rc  << " " << sqlite3_errmsg(pDB)<<  std::endl;
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    return false;
  }
	rc = sqlite3_bind_text(pStmt,1,username.c_str(),username.size(),nullptr);
	
	
  if (SQLITE_ROW != (rc=sqlite3_step(pStmt)))
  {
    //if arguments not placed into the table
    std::cout << "Failed to count the username: " << rc  << " " << sqlite3_errmsg(pDB)<<  std::endl;
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
	
	bool exists = (sqlite3_column_int(pStmt,0) > 0);
	
	sqlite3_finalize(pStmt);
	sqlite3_close(pDB);
	
	return exists;
}



//this function creates a username and password in an sqlite database

bool create_password (std::string password, const std::string &username, const std::string &database)
{

  int rc;
  if (SQLITE_OK != (rc = sqlite3_initialize())) 
  {
    std::cout << "Failed to initialize library: " << rc << std::endl;
    return false;
  }

  //first we open the database 
  sqlite3 *pDB;
  if (SQLITE_OK != (rc= sqlite3_open_v2(database.c_str(),&pDB,SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)))
  {
    std::cout << "Failed to open database: " << rc << std::endl;
    return false;
  }
  
  //this is for the hashed password 
  std::string hashed;
  //we create a 32 bit string to ne added to the password
  //salt is unknown to everyone and a new salt is create each time
  std::string salt = create_salt();

  password += salt;
  //now we create the hash 
  hashed = create_hash(password);
  //now we create the sqlite table if the table doesn't already exits
  std::string sql= "CREATE TABLE IF NOT EXISTS users( USERNAME TEXT NOT NULL, PASSWORD TEXT NOT NULL, SALT TEXT NOT NULL);";

sqlite3_stmt *pStmt = nullptr;
 if (SQLITE_OK != (rc=sqlite3_prepare_v2(pDB,sql.c_str(),sql.size(),&pStmt,nullptr)))
//if table was not created
{
  std::cout << "Failed to create table: " << rc << sqlite3_errmsg(pDB) << std::endl;
  sqlite3_finalize(pStmt);
  sqlite3_close(pDB);
  return false;
}
if (SQLITE_DONE != (sqlite3_step(pStmt)))
{
   std::cout << "Didn't Create Table!" <<std::endl;
   sqlite3_finalize(pStmt);
   sqlite3_close(pDB);
   return false;
  }
  if (SQLITE_OK !=(rc=sqlite3_finalize(pStmt)))
  std::cout << "Failed to create table!: " << rc << sqlite3_errmsg(pDB) << std::endl;

  //check to see if user name exits
  if(check_username(username, database))
  {
    std::cout << "USERNAME ALREADY IN USE!!" << std::endl;
    return false; // user already exists
  }

//if we are here then the table created or alreasy existed now we insert the data 
  sql= "INSERT INTO users (USERNAME, PASSWORD, SALT)" 
   "VALUES (?1,?2,?3)";

 if (SQLITE_OK != (rc=sqlite3_prepare_v2(pDB,sql.c_str(),sql.size(),&pStmt,nullptr)))
  {
    std::cout << "Failed to prepare username,password,and salt: " << rc  << " " << sqlite3_errmsg(pDB)<<  std::endl;
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
//now we bind the arguments to the statement to be givin to sqlite3

rc =  sqlite3_bind_text(pStmt,1,username.c_str(),username.size(),nullptr);
rc =   sqlite3_bind_text(pStmt,2,hashed.c_str(),hashed.size(),nullptr);
  rc = sqlite3_bind_text(pStmt,3,salt.c_str(),salt.size(),nullptr);
//now we place our sql statement with the arguments bound to it in our table
  if (SQLITE_DONE != (rc=sqlite3_step(pStmt)))
  {
    //if arguments not placed into the table
    std::cout << "Failed to insert username,password,and salt: " << rc  << " " << sqlite3_errmsg(pDB)<<  std::endl;
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
//if we are here then the data was inserted _nto the database ane the username and password were successfully created
  sqlite3_finalize(pStmt);
  sqlite3_close(pDB);
  std::cout << "created table" << std::endl;
  return true;
 
}

//this function will take a password,username,and database and check the given password against the password stored in the database
bool check_password (std::string password, const std::string &username, const std::string &database)
{
  //first we open the database 
  sqlite3 *pDB;
  int rc;
   if (SQLITE_OK != (rc= sqlite3_open(database.c_str(),&pDB)))
    return false;
  
   //now we create our sqlite3 string to select the password from the table where the user name matches
  std::string sql= "SELECT PASSWORD, SALT FROM users WHERE USERNAME =?";
  sqlite3_stmt *pStmt= nullptr;
  if (SQLITE_OK != (rc= sqlite3_prepare_v2(pDB,sql.c_str(),sql.size(),&pStmt,nullptr)))
  {
    //if it fails
    std::cout << "Failed to prepare select for passwor and salt string: " << rc << " " << sqlite3_errmsg(pDB) << std::endl;
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    return false;
  }
  //now we bind the username to the sqlite3 statement
  rc = sqlite3_bind_text(pStmt,1,username.c_str(),username.size(),nullptr);
 //check for password and salt 
  if (SQLITE_ROW != (rc=sqlite3_step(pStmt)))
  { 
      std::cout << "Failed to select password and salt: " << rc << " " << sqlite3_errmsg(pDB) << std::endl; 
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    return false;
  }
  
  //if we are still here password and salt were found
  std::string salt;
  std::string curPword;
  
  //assign them to their respective strings
  curPword.assign((const char*)sqlite3_column_text(pStmt,0), sqlite3_column_bytes(pStmt,0));
  
  salt.assign((const char*)sqlite3_column_text(pStmt,1), sqlite3_column_bytes(pStmt,1));

  sqlite3_finalize(pStmt);
  sqlite3_close(pDB);
  
  //now we compare then given password to the password stored in the database 
  //firsr we must hash the password given using (hensalt that was stored in the database 
  std::string hashed;
  password += salt;
  hashed = create_hash(password);

  return hashed==curPword;
}

//this function will allow us to change a password at a given username
bool change_password (std::string password, const std::string &username, const std::string &database)
{
  //first we open the database 
  sqlite3 *pDB;
  sqlite3_stmt *pStmt = nullptr;
  int rc;

  if (SQLITE_OK != (rc= sqlite3_open(database.c_str(),&pDB)))
    return false;
  
  //now we prepare our sqlite3 statement
  std::string sql= "UPDATE users SET PASSWORD =?1,SALT=?2 WHERE USERNAME =?3";

  if (SQLITE_OK != (rc= sqlite3_prepare_v2(pDB,sql.c_str(),sql.size(),&pStmt,nullptr)))
  {
    std::cout << "Failed to prepare  password: " << rc << " " << sqlite3_errmsg(pDB) << std::endl;
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    return false;
  }

  //now lets generate a new salt and hash the password 
  std::string salt= create_salt();
  password += salt;
  std::string hashed = create_hash(password);
 
//now we bind the usename, password, and salt.
  rc= sqlite3_bind_text(pStmt,1,hashed.c_str(),hashed.size(),nullptr);
  rc= sqlite3_bind_text(pStmt,2,salt.c_str(),salt.size(),nullptr);
  rc= sqlite3_bind_text(pStmt,3,username.c_str(),username.size(),nullptr);

  if (SQLITE_DONE != (rc=sqlite3_step(pStmt) ))
   {
     std::cout <<"Failed to insert password and salt!:"<< rc  << sqlite3_errmsg(pDB) << std::endl;
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    return false;
   }
 
  //if we are here then the salt w&s changed, thus we have updated our (hashed) password as well as the salt
  sqlite3_close(pDB);
  sqlite3_finalize(pStmt);

  return true; 
}

//this function will create thensalt added to the password
std::string create_salt()
{
  //characters used to produce the salt
  const char alphanum[]= "0123456789"
                        "!@#$%&^"
                "abcdefghijklmnopqrstuvwxyz"
               " ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  int stringLength = sizeof(alphanum)-1;
  //the followingnwill be used to generate our random number to be used as an index into our alphanum 
  std::random_device rd;
  static std::mt19937 mt(rd());
  std::string salt;
  //now we create our salt
  for (int i=0;i<30;++i)
  {
    //although it goes against convention, instantiating the distribution inside of the loop actually speeds the algorithm up by almost 1/3µm, as noted by Mr.Cheinan Marks at CppCon 2016
    std::uniform_int_distribution<int> dist(0,stringLength);
    salt.push_back(alphanum[dist(mt)]);
  }
  return salt;
}
