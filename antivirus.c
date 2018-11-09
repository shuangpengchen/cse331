#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>




	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream){
  		size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  		return written;
	}
	


	int main(int argc, char *argv[]){
		//cmd options
		const char *load="-load";
		const char *unload="-unload";
		const char *update="-update";
		const char *scan="-scan";
		
		//files and urls
		static const char *whitelistfilename = "whitelist.out";
  		static const char *signaturefilename = "signature.out";
  		static const char *signatureUrl = "http://35.231.146.204/signature.db";
        static const char *whitelistUrl = "http://35.231.146.204/whitelist.db";
		
		//usage printout
		const char *usage = "\nUsage: \n" 
            				"-load  load the kernal module.\n" 
            				"-unload  unload the kernal module.\n" 
            				"-update  update virus database and whitelist database.\n" 
            				"-scan  on-demand scan\n" ;

		CURL *curl_handle;

  		FILE *pagefile;

		//var
		FILE *fp;
		int status;
		char *address;
		int buffer_size = 100;
		char buffer[buffer_size];
		char *moduleName = "hack_open.ko";


            				
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
				printf("%s\n", "2.loading module");
				
				printf("%s\n", moduleName);
				
				
			}else if(strcmp(argv[1],unload)==0){

				printf("%s\n", "unloading module....");	

			}else if(strcmp(argv[1],update)==0){
				printf("%s\n", "updating database....");	





				curl_handle = curl_easy_init();


  				curl_global_init(CURL_GLOBAL_ALL);
 
  				/* init the curl session */ 
  				curl_handle = curl_easy_init();
 
  		//--- for signature file download
				/* set URL to get here */ 
  				curl_easy_setopt(curl_handle, CURLOPT_URL, signatureUrl);
  				/* Switch on full protocol/debug output while testing */ 
  				curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  				/* disable progress meter, set to 0L to enable and disable debug output */ 
  				curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
  				/* send all data to this function  */ 
  				curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
 
  				/* open the file */ 
  				pagefile = fopen(signaturefilename, "wb");
  				if(pagefile) {
    				/* write the page body to this file handle */ 
    				curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
    				/* get it! */ 
    				curl_easy_perform(curl_handle);
    				/* close the header file */ 
    				fclose(pagefile);
  				}

  				printf("%s\n", "signature file updated...");



  		//--- for whitelist file download
  				/* set URL to get here */ 
  				curl_easy_setopt(curl_handle, CURLOPT_URL, whitelistUrl);
  				/* Switch on full protocol/debug output while testing */ 
  				curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  				/* disable progress meter, set to 0L to enable and disable debug output */ 
  				curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
  				/* send all data to this function  */ 
  				curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
 
  				/* open the file */ 
  				pagefile = fopen(whitelistfilename, "wb");
  				if(pagefile) {
    				/* write the page body to this file handle */ 
    				curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
    				/* get it! */ 
    				curl_easy_perform(curl_handle);
    				/* close the header file */ 
    				fclose(pagefile);
  				}

  				printf("%s\n", "whitelist file updated...");


 		//---clean up
  				/* cleanup curl stuff */ 
  				curl_easy_cleanup(curl_handle);
  				curl_global_cleanup();

  				printf("%s\n", "done updating database");



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

