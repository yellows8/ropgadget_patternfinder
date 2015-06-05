#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/sha.h>

//Build with: gcc -o ropgadget_patternfinder ropgadget_patternfinder.c -lcrypto

int load_bindata(char *arg, unsigned char **buf, unsigned int *size)
{
	int i;
	unsigned int tmp=0;
	unsigned char *bufptr;
	FILE *f;
	struct stat filestat;

	bufptr = *buf;

	if(arg[0]!='@')
	{
		if(bufptr==NULL)
		{
			tmp = strlen(arg);
			if(tmp<2 || (tmp & 1))
			{
				printf("The length of the input hex param is invalid.\n");
				return 4;
			}

			*size = strlen(arg) / 2;
			*buf = (unsigned char*)malloc(*size);
			bufptr = *buf;
			if(bufptr==NULL)
			{
				printf("Failed to allocate memory for input buffer.\n");
				return 1;
			}

			memset(bufptr, 0, *size);
		}

		for(i=0; i<*size; i++)
		{
			if(i>=strlen(arg))break;
			sscanf(&arg[i*2], "%02x", &tmp);
			bufptr[i] = (unsigned char)tmp;
		}
	}
	else
	{
		if(stat(&arg[1], &filestat)==-1)
		{
			printf("Failed to stat %s\n", &arg[1]);
			return 2;
		}

		f = fopen(&arg[1], "rb");
		if(f==NULL)
		{
			printf("Failed to open %s\n", &arg[1]);
			return 2;
		}

		if(bufptr)
		{
			if(*size < filestat.st_size)*size = filestat.st_size;
		}
		else
		{
			*size = filestat.st_size;
			*buf = (unsigned char*)malloc(*size);
			bufptr = *buf;

			if(bufptr==NULL)
			{
				printf("Failed to allocate memory for input buffer.\n");
				return 1;
			}

			memset(bufptr, 0, *size);
		}

		if(fread(bufptr, 1, *size, f) != *size)
		{
			printf("Failed to read file %s\n", &arg[1]);
			fclose(f);
			return 3;
		}

		fclose(f);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int argi;
	int ret;
	int hashpattern_set = 0;
	int found;
	unsigned char *filebuf = NULL;
	unsigned char inhash[0x20];
	unsigned char calchash[0x20];
	unsigned char *inhashptr;
	size_t filebufsz=0, pos, hashblocksize=0;
	unsigned int tmpsize=0;
	struct stat filestat;
	FILE *fbin;

	if(argc<3)
	{
		printf("ropgadget_patternfinder by yellows8.\n");
		printf("Locates the offset/address of the specified pattern in the input binary. This tool is mainly intended for locating ROP-gadgets, but it could be used for other purposes as well.\n");
		printf("<bindata> below can be either hex with any byte-length(unless specified otherwise), or '@' followed by a file-path to load the data from.");
		printf("Usage:\n");
		printf("ropgadget_patternfinder <binary path> <options>\n");
		printf("Options:\n");
		printf("--patternsha256=<bindata> Hash every --patternsha256size bytes in the binary, for locating the target pattern. The input bindata(sha256 hash) size must be 0x20-bytes.\n");
		printf("--patternsha256size=0x<hexval> See --patternsha256.\n");

		return 0;
	}

	ret = 0;

	for(argi=2; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--patternsha256=", 16)==0)
		{
			if(strlen(&argv[argi][16]) != 0x20*2)
			{
				printf("Input sha256 hash size is invalid.\n");
				ret = 5;
			}
			else
			{
				inhashptr = inhash;
				tmpsize = 0x20;
				ret = load_bindata(&argv[argi][16], &inhashptr, &tmpsize);
				if(ret==0)hashpattern_set = 1;
			}
		}

		if(strncmp(argv[argi], "--patternsha256size=", 20)==0)
		{
			sscanf(&argv[argi][20], "0x%x", &tmpsize);
			hashblocksize = tmpsize;
		}

		if(ret!=0)break;
	}

	if(ret!=0)return ret;

	if(hashpattern_set && hashblocksize==0)
	{
		printf("--patternsha256size must be used when --patternsha256 is used.\n");
		return 5;
	}

	if(!hashpattern_set)
	{
		printf("No pattern specified.\n");
		return 5;
	}

	if(stat(argv[1], &filestat)==-1)
	{
		printf("Failed to stat the input binary: %s.\n", argv[1]);
		return 1;
	}

	filebufsz = filestat.st_size;
	filebuf = malloc(filebufsz);
	if(filebuf==NULL)
	{
		printf("Failed to alloc filebuf.\n");
		return 2;
	}

	fbin = fopen(argv[1], "rb");
	if(fbin==NULL)
	{
		printf("Failed to open the input binary.\n");
		free(filebuf);
		return 3;
	}

	if(fread(filebuf, 1, filebufsz, fbin) != filebufsz)
	{
		printf("Failed to read the input binary.\n");
		free(filebuf);
		fclose(fbin);
		return 4;
	}

	fclose(fbin);

	found = 0;
	ret = 0;

	for(pos=0; pos<filebufsz; pos+=4)
	{
		if(filebufsz - pos < hashblocksize)break;

		SHA256(&filebuf[pos], hashblocksize, calchash);
		if(memcmp(inhash, calchash, 0x20)==0)
		{
			found = 1;
			break;
		}
	}

	if(!found)
	{
		printf("Failed to find the pattern.\n");
		ret = 7;
	}
	else
	{
		printf("Found the pattern at 0x%x.\n", (unsigned int)pos);
	}

	free(filebuf);

	return ret;
}

