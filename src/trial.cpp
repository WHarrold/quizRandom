#include<string>
#include<iostream>
#include"headers/crypto.h"

using namespace std;

int main ()
{
  cout << "thiss is antest of crypto library." << endl;
  cout << "this will check we get the same password every time" << endl;

  cout << "create hash:" << endl;
  string rightpword ( "right password");
  string wrongpword ( "wrong password");
  string hashed;
  for(int i=0;i<5;++i){
    hashed = create_hash(rightpword);
    cout << hashed << endl;
  }
 
  string db= "data.dat";
  string un= "thug rose";
  bool rc;

  cout << "creating password" << endl;
  rc = create_password(hashed,un,db);
  if (rc)
    cout << "password was created" << endl;
  else
    cout << "password was not creates" << endl;
  cout<< "check password" << endl;
  cout << "checking right password:" << endl;
  rc = check_password (rightpword,un,db);
  if (rc)
    cout << "this password is correct" << endl;
  else
    cout << "this password is incorrect" << endl;
 cout << "checking wrong password" << endl;
 rc = check_password(wrongpword,un,db);
 if (rc)
    cout << "this password is correct" << endl;
 else
    cout << "this password is incorrect" << endl;
 cout << "changing password" << endl;
 string _new("anny");
 rc= change_password(_new,un,db);
  if (rc)
    cout << "this password is correct" << endl;
  else
    cout << "this password is incorrect" << endl;
   
 cout << "just for kicks let's check the new password" << endl;
 rc = check_password(_new,un,db);
 if (rc)
    cout << "this password is correct" << endl;
else
    cout << "this password is incorrect" << endl; 
  return 0;
}
