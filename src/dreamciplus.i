 /* dreamciplus.i */
 %module dreamciplus
 %{
 extern int start(int slot);
 extern int restart(int slot);
 extern int stop(int slot);
 extern int setInit(int slot);
 extern int setReset(int slot);
 extern int setErase(int slot);
 extern int getVersion();
 %}

 extern int start(int slot);
 extern int restart(int slot);
 extern int stop(int slot);
 extern int setInit(int slot);
 extern int setReset(int slot);
 extern int setErase(int slot);
 extern int getVersion();
