#include <stdio.h>
#include <string.h>
#include <stdlib.h>

	int main(int argc, char *argv[]){
		//const
		const char *load="-load";
		const char *unload="-unload";
		const char *update="-update";
		const char *scan="-scan";

		//var
		FILE *fp;
		int status;
		char *address;
		int buffer_size = 100;
		char buffer[buffer_size];




		const char *usage = "\nUsage: \n" 
            				"-load  load the kernal module.\n" 
            				"-unload  unload the kernal module.\n" 
            				"-update  update virus database and whitelist database.\n" 
            				"-scan  on-demand scan\n" ;
            				
		if(argc == 2 ){
			if(strcmp(argv[1],load)==0){
				printf("%s\n", "loading module....");
				printf("%s\n", "1.get sys_call_table address....");
				fp=popen("sudo cat /boot/System.map-*-generic| grep sys_call_table | awk '{print $1}'","r");
				if(fp == NULL){
					printf("step 1 failed");
					exit(-1);
				}
				address = malloc(sizeof(char)*buffer_size);
				fgets(buffer,buffer_size,fp);
				strcpy(address,buffer);
				printf("++address: %s\n", buffer );
				fclose(fp);
			}else if(strcmp(argv[1],unload)==0){
				printf("%s\n", "unloading module....");	
			}else if(strcmp(argv[1],update)==0){
				printf("%s\n", "updating database....");	
			}else{
				printf("Error: incorrect usage.\n%s\n", usage);
			}
		}
		else if(argc ==3){
			if(strcmp(argv[1],scan)==0){
				printf("%s\n", "on-demand scan....");
			}else{
				printf("Error: incorrect usage.\n%s\n", usage);
			}
		}else{
			printf("Error: incorrect usage.\n%s\n", usage);
		}
		return 0;
	}

