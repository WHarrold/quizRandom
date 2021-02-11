//implmentqtion file for crypto.h
#include<string>
#include<cstring>
#include<random>
#include"crypto.h"
#include <openssl/evp.h>
#include "openssl/sha.h"
#include"sqlite/build/sqlite3.h"

//thus functiin takes a string, which will be a password but could be used to hash any string, it using the sha512 algorithm
std::string create_hash(const std::string &input)
{
  int iter = 1007;

  const unsigned char *salt = nullptr;
  unsigned char key[32] = {0};

  PKCS5_PBKDF2_HMAC(input.c_str(), inp        ut.size(),
        salt, 0,
        iter, EVP_sha256(),
        sizeof(key), key);

  std::string hashed = key;
  return hashed;

}

//this function creates a username and password in an sqlite database

bool create_password (std::string password, const std::string &username, const std::string &database)
{
  //first we open the database 
  sqlite3 *pDB;
  int rc= sqlite3_open(database.c_str(),&pDB);
  if (rc != SQLITE_OK)
    return false;
  //this is for the hashed password 
  std::string hashed;
  //we create a 32 bit string to ne added to the password
  //salt is unknown to everyone and a new salt is create each time
  str::string salt = create_salt();

  password += salt;
  //now we create the hash 
  hashed = create_hash(password);
  //now we create the sqlite table if the table doesn't already exits
  std::string sql= "CREATE TABLE IF NOT EXISTS UESERS("
                  "USERNAME   TEXT NOT NULL,"
                  "PASSWORD   TEXT NOT NULL,"
                  "SALT       TEXT NOT NULL);";
  sqlite3_stmt *pStmt = nullptr;
  rc = sqlite3_prepare_v2(pDB,sql.c_str(),sql.size()+1,&pStmt,nullptr);
  //if table was not created
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  //if we are here then the table created or alreasy existed now we insert the data 
  sql= "INSERT INTO USERS (USERNAME,PASSWORD,SALT)"
       "VALUES (?,?,?)";
  rc = sqlite3_prepare_v2(pDB,sql.c_str(),sql.size()+1,&pStmt,nullptr);

  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  //now we bind the arguments to the statement to be givin to sqlite3
  rc = sqlite3_bind_text(pStmt,1,username.c_str(),username.size()+1,nullptr);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  rc = sqlite3_bind_text(pStmt,2,username.c_str(),username.size()+1,nullptr);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  rc = sqlite3_bind_text(pStmt,3,username.c_str(),username.size()+1,nullptr);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  //now we place our sql statement with the arguments bound to it in our table
  //if arguments not placed into the table
  if (sqlite3_step(pStmt) != SQLITE_DONE)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  //ifnwe are here then the data was inserted _nto the database ane the username and password were successfully created
  sqlite3_close(pDB);
  sqlite3_finalize(pStmt);
  return true;
}

//this function will take a password,username,and database and check the given password against the password stored in the database
bool check_password (std::string password, const std::string &username, const std::string &database)
{
  //first we open the database 
  sqlite3 *pDB;
  int rc= sqlite3_open(database.c_str(),&pDB);
  if (rc != SQLITE_OK)
    return false;
  //now we create our sqlite3 string to select the password from the table where the user name matches
  std::string sql= "SELECT PASSWORD FROM USERS"
                  "WHERE USERNAME =?";
  sqlite3_stmt *pStmt= nullptr;
  rc= sqlite3_prepare_v2(pDB,sql.c_str(),sql.size()+1,&pStmt,nullptr);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  //now we bind the username to the sqlite3 statement
  rc= sqlite3_bind_text(pStmt,1,username.c_str(),username.size()+1,nullptr);
   if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  std::string salt;
  std::string strBuffer;
  char cBuffer[1024];
  std::string curPword;
  //check for username 
  if (sqlite3_step(pStmt) != SQLITE_ROW)
   {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
   }
  //if we are still here username was found
  sprintf(cBuffer,"%s",sqlite3_column_text(pStmt,1));
  strBuffer= cBuffer;
  curPword= strBuffer;
  sqlite3_finalize(pStmt);
  sql= "SELECT,SALT FROM USERS WHERE"
       "USERNAME =?";
  rc= sqlite3_bind_text(pStmt,1,username.c_str(),username.size()+1,nullptr);
   if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  char bBuffer[1024];
  if (sqlite3_step(pStmt) != SQLITE_ROW)
   {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
   }
  //if we are still here username was found
  sprintf(bBuffer,"%s",sqlite3_column_text(pStmt,2));
  strBuffer= bBuffer;
  salt= strBuffer;
  sqlite3_finalize(pStmt);
  sqlite3_close(pDB);
  //now we compare thengiven password to the password stored in the database 
  //firsr we must hash the password given using (hensalt that was stored in the database 
  std::string hashed;
  password += salt;
  hashed=create_hash(password);

  return hashed==curPword;
}

//this function will allow us to change a password at a given username
bool change_password (std::string password, const std::string &username, const std::string &database)
{
  //first we open the database 
  sqlite3 *pDB;
  int rc= sqlite3_open(database.c_str(),&pDB);
  if (rc != SQLITE_OK)
    return false;
  //now we prepare our sqlite3 statement
  std::string sql= "UPDATE USERS SET PASSWORD =?1"
                   "WHERE USERNAME =?2";
  //now lets generate a new salt and hash the password 
  std::string salt= create_salt();
  password += salt;
  std::string hashed = create_hash(password);
  //now we bind the usename and password
  sqlite3_stmt *pStmt = nullptr;
  rc= sqlite3_prepare_v2(pDB,sql.c_str(),sql.size()+1,&pStmt,nullptr);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
rc= sqlite3_bind_text(pStmt,2,username.c_str(),username.size()+1,nullptr);
   if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  rc= sqlite3_bind_text(pStmt,1,password.c_str(),password.size()+1,nullptr);
   if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  if (sqlite3_step(pStmt) != SQLITE_DONE)
   {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
   }
  //now we must change the salt to the new one
  sql= "UPDATE USERS SET SALT =?1"
               "WHERE USERNAME =?2";
  sqlite3_finalize(pStmt);
  rc= sqlite3_prepare_v2(pDB,sql.c_str(),sql.size()+1,&pStmt,nullptr);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
rc= sqlite3_bind_text(pStmt,2,username.c_str(),username.size()+1,nullptr);
   if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  rc= sqlite3_bind_text(pStmt,1,salt.c_str(),salt.size()+1,nullptr);
   if (rc != SQLITE_OK)
  {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
    return false;
  }
  if (sqlite3_step(pStmt) != SQLITE_DONE)
   {
    sqlite3_close(pDB);
    sqlite3_finalize(pStmt);
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
  for (int i=0;i<36;++i)
  {
    //although it goes against convention, instantiating the distribution inside of the loop actually speeds the algorithm up by almost 1/3µm, as noted by Mr.Cheinan Marks at CppCon 2016
    std::uniform_int_distribution<int> dist(0,stringLength);
    salt.push_back(alphanum[dist(mt)]);
  }
  return salt;
}
