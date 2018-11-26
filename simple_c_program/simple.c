#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>



	int main(int argc, char *argv[]){
		FILE *fp;
		char temp[300];
		strcpy(temp,"echo '1' > /dev/anti");

		fp = popen(temp,"r");
		if(fp ==NULL){
			printf("%s\n", "fail to write to device: anti");
			exit(-1);
		}
	}
		