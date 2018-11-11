#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <dirent.h>





	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream){
  		size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  		return written;
	}

	void scan_core(const char* file_name){
		FILE *file;
		FILE *wl_or_sig;
		FILE *fp;
		static const char *whitelistfilename = "whitelist.out";
  		static const char *signaturefilename = "signature.out";
		char tartget_file_hash[PATH_MAX];
		char wl_content[PATH_MAX];


		file = fopen(file_name,"r");
		if(file ==NULL){
			printf("failed to open target file : %s\n",file_name);
			exit(-1);
		}
		char temp[300];
		strcpy(temp,"shasum ");
		strcat(temp,file_name);
		strcat(temp," | awk '{print $1}'");
		fp = popen(temp,"r");

		if(fp ==NULL){
			printf("%s\n", "fail to hash file");
			exit(-1);
		}
		
		if( (fgets(tartget_file_hash, PATH_MAX, fp)) == NULL){
			printf("%s\n","hash failed.." );
			exit(-1);
		}    
    	pclose(fp);
    	strtok(tartget_file_hash,"\n");
    	printf("tartget_file_hash is :%s\n", tartget_file_hash);


    	printf("%s\n","opening wl file" );
    	wl_or_sig = fopen(whitelistfilename,"r");
    	if(wl_or_sig == NULL){
    		printf("%s\n","fail to open whitelist file" );
    		exit(-1);
    	}

    	printf("%s\n","1.reading from whitelist file" );

    	bool need2scan=true;
    	while((fgets(wl_content, PATH_MAX, fp)) != NULL){
    		strtok(wl_content,"\n");
    		if(strcmp(wl_content,"543d684d7f95c6c7bc1aa979ce2109f3075a9688") == 0){
    			printf("%s\n", "whitelist file has a match.");
    			need2scan=false;
    			break;
    		}
    	}

    	if(need2scan){
    		printf("%s\n", "need to scan");
    	}else{
    		printf("%s\n", "file is in whitelist..");
    		return;
    	}





	}


	bool is_dir(const char* path){
		struct stat buf;
		stat(path,&buf);
    	return S_ISDIR(buf.st_mode);
	}

	 void scan_f(const char* start_path){
		 
		 if(is_dir(start_path)){
		 	    DIR *dir;
		 	    char path[1000];

		 	    struct dirent *entry;
		 	    dir = opendir(start_path);
		 	    if(dir){
		 	    	while((entry = readdir(dir)) != NULL){
		 	    		if(strcmp(entry->d_name,".")!=0 && strcmp(entry->d_name,"..")!=0){
							strcpy(path,start_path);
		 	    			strcat(path,"/");
		 	    			strcat(path,entry->d_name);
		 	    			scan_f(path);
		 	    		}
		 	    	}
		 	    	closedir(dir);
		 	    }
		 	    return;
		 }else{
		 	printf("Scanning file: %s\n", start_path);
		 	scan_core(start_path);
		 }
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
				printf(" loading module : %s\n", moduleName);
				fp=popen("sudo insmod hack_open.ko","r");
				if(fp == NULL){
					printf("step 2 failed");
					exit(-1);
				}
				printf("%s\n","module is loaded now, check it with dmesg cmd");
				fclose(fp);
			}else if(strcmp(argv[1],unload)==0){
				fp= popen("sudo rmmod hack_open","r");
				if(fp == NULL){
					printf("error unloading module");
					exit(-1);
				}
				printf("%s\n", "module unloaded. check with dmesg!");	
				fclose(fp);
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

				scan_f(argv[2]);

				




			}else{
				printf("Error: incorrect usage.\n%s\n", usage);
			}
		}else{
			printf("Error: incorrect usage.\n%s\n", usage);
		}
		return 0;
	}

