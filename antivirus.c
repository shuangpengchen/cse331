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

  





	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream){
  		size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  		return written;
	}

	int getsize(char s[]){
   		int c = 0;
   		while (s[c] != '\0')
      		c++;
   		return c;
	}

	int ascii_to_hex(char c)
	{
        int num = (int) c;
        if(num < 58 && num > 47){
                return num - 48; 
        }
        if(num < 103 && num > 96){
                return num - 87;
        }
        return num;
	}

	void hex2ascii(char *hexsig, int size, unsigned char *address){
		unsigned char one;
		unsigned char two;
		unsigned char sum;
		unsigned char final_hex[size/2];
		for(int i=0;i<size/2;i++){
			one = ascii_to_hex(hexsig[i*2]);
			two = ascii_to_hex(hexsig[i*2+1]);
			sum = one << 4 | two;
			final_hex[i] = sum;
		}
		memcpy(address,final_hex,sizeof(unsigned char) * size / 2);
	}

	unsigned char** processSig(unsigned char **sigs,int *sigNumber,int **sigs_length,const char *signaturefilename){
		FILE *sigfile;
		char sig_buffer[PATH_MAX];
		sigfile = fopen(signaturefilename,"r");
		if(sigfile ==NULL){
			printf("%s\n", "failed to open sigfile");
			exit(-1);
		}
		int counter=0;
		while((fgets(sig_buffer,PATH_MAX,sigfile))!=NULL){
			counter++;
		}
		*sigNumber = counter;
		fclose(sigfile);
		sigs = malloc(sizeof(unsigned char *) * counter);
		*sigs_length = malloc( sizeof(int) * counter );
		sigfile = fopen(signaturefilename,"r");
		int i=0;
		while((fgets(sig_buffer,PATH_MAX,sigfile))!=NULL){
			strtok(sig_buffer,"\n");
			int size = getsize(sig_buffer);
			(*sigs_length)[i] = size/2;
			if((sigs[i] = malloc(sizeof(unsigned char) * size / 2))==NULL){
				printf("%s\n", "failed to alloc memory for array element.");
				exit(-1);
			}
			hex2ascii(sig_buffer,size,sigs[i]);
			i++;
		}
		return sigs;
	}


	void scan_core(const char* file_name,unsigned char** sigs,int *sigs_length,int sigNumber){
		FILE *file;
		FILE *wl_or_sig;
		FILE *fp;
		char new_name[strlen(file_name)+9];
		static const char *whitelistfilename = "whitelist.out";
  		static const char *signaturefilename = "signature.out";
		char target_file_hash[PATH_MAX];
		char wl_content[PATH_MAX];
		file = fopen(file_name,"r");
		if(file ==NULL){
			printf("ERROR: Failed to open target file : %s\n",file_name);
			return;
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
		
		if( (fgets(target_file_hash, PATH_MAX, fp)) == NULL){
			printf("%s\n","hash failed.." );
			exit(-1);
		}    
    	pclose(fp);
    	strtok(target_file_hash,"\n");
    	printf("MESSAGE: Hash of target file is :%s\n", target_file_hash);
    	wl_or_sig = fopen(whitelistfilename,"r");
    	if(wl_or_sig == NULL){
    		printf("%s\n","fail to open whitelist file" );
    		exit(-1);
    	}
    	bool need2scan=true;
    	while((fgets(wl_content, PATH_MAX, wl_or_sig)) != NULL){
    		strtok(wl_content,"\n");
    		if(strcmp(wl_content,target_file_hash) == 0){
    			printf("%s\n", "whitelist file has a match.");
    			need2scan=false;
    			break;
    		}
    	}
    	fclose(wl_or_sig);
    	if(need2scan){
    		printf("STATUS: %s\n", "need to scan");
    		//get target file size
    		fseek(file, 0L, SEEK_END);
    		int targetfilesize = ftell(file);
			fseek(file, 0L, SEEK_SET);
    		//get the max and min lengths in sigs
    		int min=0;
    		int max=0;
    		for(int i=0;i<sigNumber;i++){    			
    			int length = sigs_length[i];
    			if(min==0 && max ==0){
    				min =length;
    				max = length;
    			}else if(length > max){
    				max = length;
    			}else if(length < min){
    				min = length;
    			}
    		}
    		
    		//main scan  functionality
    		int offset =0;
    		int seek = targetfilesize - max + 1;
    		int seekend = targetfilesize - min;
    		unsigned char file_fraction_buffer[max];
    		bool sig_matched = false;
    		while(offset != seek){
    			fseek(file, offset, SEEK_SET);
    			int read_size = fread(file_fraction_buffer,sizeof(unsigned char),max,file);
    			//printf("just read in %d bytes of char from file\n", read_size);
    			if(read_size != max){
    				printf("WHAT IS GOING ON????   only read %d bytes ?\n", read_size);
    			}
    			// cmp goes here
    			for(int i=0;i<sigNumber;i++){
    				int count_the_match_c =0;
    				for(int j=0;j<sigs_length[i];j++){
    					if(file_fraction_buffer[j] != sigs[i][j] ){
    						count_the_match_c=0;
    						break;
    					}else{
    						count_the_match_c++;
    					}
    				}
    				if(count_the_match_c == sigs_length[i]){
    					sig_matched=true;
    					break;
    				}
    			}


    			// change the offset from the begin of file
    			offset++;

    			//last part of file in buffer with length max
    			if(offset == seek){
    				// final cmp goes here

    				int offset2 = offset-1;
    				int tempsize = max-1;
    				while(offset2 != seekend){
						fseek(file, offset2, SEEK_SET);
						int read_size1 = fread(file_fraction_buffer,sizeof(unsigned char),tempsize,file);
						//printf("IN FINAL PART: read in %d bytes\n", read_size1);
						for(int i=0;i<sigNumber;i++){
    						int count_the_match_c2 =0;
    						if(sigs_length[i] < read_size1){
    							continue;
    						}else{
    							if(sigs_length[i] == min){
    								//printf("%s and min is %d\n", "------------------down goes the min detection++++++++++",min);
    							}
    							for(int j=0;j<sigs_length[i];j++){
    								if(sigs_length[i] == min){
    									//printf("sig: %02x and file bytes is %02x\n", sigs[i][j] , file_fraction_buffer[j] );
    								}
    								if(file_fraction_buffer[j] != sigs[i][j] ){
    									count_the_match_c2=0;
    									break;
    								}else{
    									count_the_match_c2++;
    								}
    							}	
    						}
    						
    						if(count_the_match_c2 == sigs_length[i]){
    							sig_matched=true;
    							//printf("count_the_match_c2 is %d and sigs_length[i] is %d : %s\n", count_the_match_c2,sigs_length[i],"match");
    							break;
    						}else{
    						}
    					}

    				offset2++;
    				tempsize--;
    				}

    			}







    			if(sig_matched){ // rename and remove permission
					printf("MESSAGE: %s\n", "Removing permissions...");
					struct stat st;
    				mode_t mode;
    				stat(file_name, &st);
    				mode = st.st_mode & 00000;
    				chmod(file_name, mode);
    				printf("WARNING: %s\n", "The file contain malicious code");
    				printf("MESSAGE: %s\n", "Renaming file...");
    				strcpy(new_name,file_name);
    				strcat(new_name,".infected");
    				rename(file_name,new_name);
    				break;
    			}
    		}
    		if(!sig_matched){
    			printf("MESSAGE: %s\n", "File is safe");		
    		}
    	}else{
    		printf("-------------------------\n%s\n-------------------------\n", "file is in whitelist..");
    	}
    	fclose(file); // close the target file
	}


	bool is_dir(const char* path){
		struct stat buf;
		stat(path,&buf);
    	return S_ISDIR(buf.st_mode);
	}

	 void scan_f(const char* start_path,unsigned char** sigs, int* sigs_length,int sigNumber){
		 
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
		 	    			scan_f(path,sigs,sigs_length,sigNumber);
		 	    		}
		 	    	}
		 	    	closedir(dir);
		 	    }
		 	    return;
		 }else{
		 	printf("Scanning file: %s\n", start_path);
		 	scan_core(start_path,sigs,sigs_length,sigNumber);
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

		//var
		FILE *fp;
		CURL *curl_handle;
  		FILE *pagefile;
        unsigned char **sigs;		//save all the sigs in heap 
        int *sigs_length;
        int sigNumber=0;
		int status;

		char *address;
		int buffer_size = 100;
		char buffer[buffer_size];
		// should be change when module is ready
		char *moduleName = "hack_open.ko";


		//testing 
		//int BUFSIZ = 1024;
		

		if(argc == 2 ){
			if(strcmp(argv[1],load)==0){
				printf("%s\n", "loading module....");
				printf("%s\n", "1.get sys_call_table address....");
				fp=popen("sudo cat /boot/System.map-*-generic| grep sys_call_table | awk '{print $1}'","r");
				if(fp == NULL){
					printf("step 1 failed");
					exit(-1);
				}
				address = malloc(sizeof( char)*buffer_size);
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
				sigs = processSig(sigs,&sigNumber,&sigs_length,signaturefilename);	//at this point sigs are in memory in ascii code
				scan_f(argv[2],sigs,sigs_length,sigNumber);
			}else{
				printf("Error: incorrect usage.\n%s\n", usage);
			}
		}else{
			printf("Error: incorrect usage.\n%s\n", usage);
		}
		return 0;
	}




	//-------testing
				// for(int i=0;i<sigNumber;i++){
				// 	printf("sigs[%d] length is  %d\n",i,sigs_length[i] );
				// }
				// for(int i=0;i<sigNumber;i++){
				// 	for(int j=0;j<sigs_length[i];j++){
				// 		printf("%02x", sigs[i][j] );
				// 	}
				// 	printf("%s","\n" );
				// }
	//-------testing

