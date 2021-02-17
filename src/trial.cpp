#include<string>
#include<iostream>
#include"headers/crypto.h"

using std::string; using std::cout; 
using std::endl;

int main ()
{
  cout << "this is a test of crypto library." << endl;
  cout << "this will check we get the same password every time" << endl;

  cout << "create hash:" << endl;
  string rightpword = "rightpassword";
  string wrongpword = "wrongpassword";
  string hashed;
  string hashed2;
  string salt;
  cout << rightpword << endl;

  for(int i=0;i<5;++i){
    salt = create_salt();
    rightpword += salt;
    hashed = create_hash(rightpword);
    hashed2 = create_hash(rightpword);
    cout << hashed << '\n'<< hashed2 << '\n'<< endl;
    (hashed == hashed2)? cout <<"hashes are equal" :cout <<"hashes are not equal" ;
    cout << endl;
  }
 
  string db= "data.db";
  string un= "thug rose";
  bool rc;

  cout << "creating password" << endl;
  rc = create_password(hashed,un,db);
  if (rc)
    cout << "password was created" << endl;
  else
    cout << "password was not created" << endl;
  cout<< '\n'<<'\n'<< "checking passwords" << endl;
  cout << "checking the right password:" << endl;
  rc = check_password (rightpword,un,db);
  if (rc)
    cout << "this password is correct" << endl;
  else
    cout << "this password is incorrect" << endl;
 cout <<'\n'<< "checking wrong password" << endl;
 rc = check_password(wrongpword,un,db);
 if (rc)
    cout << "this password is correct" << endl;
 else
    cout << "this password is incorrect" << endl;
 cout << '\n'<<'\n'<<"changing password" << endl;
 string _new("anny");
 rc= change_password(_new,un,db);
  if (rc)
    cout << "this password was changed" << endl;
  else
    cout << "this password was not changes" << endl;
   
 cout << '\n'<<'\n'<<"just for kicks let's check the new password" << endl;
 rc = check_password(_new,un,db);
 if (rc)
    cout << "this password is correct" << endl;
else
    cout << "this password is incorrect" << endl; 
  return 0;
}
