# cse331

run the following cmd to compile:
	gcc -o anti antivirus.c -lcurl
	it's possible that you will get an error about curl, that's because you haven't downloaded the curl lib yet.
 




the following are the program cmds:

./anti -update (finished,but server is down, you will not be able to downloaded anything from the server)
	will download whitelist.out file and signature.out file from server 

./anti -load (partly)
	will load the module into kernal 

./anti -unload (partly)
	will unload the module from teh kernal

./anti -scan file_or_dir (haven't implemented the permission removing part)
	this is on demand scaning 



all my signature are generated from ./sig/kittens/1.jpg to ./sig/kittens/11.jpg , so when you scan the sig/kittens file, it will marked 1.jpg - 11.jpg as infected and keeping 12.jpg - 15.jpg the same.
