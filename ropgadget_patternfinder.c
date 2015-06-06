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
	int patterntype = -1;
	unsigned int found, found2, findtarget=1;
	unsigned char *filebuf = NULL, *patterndata = NULL, *patternmask = NULL;
	unsigned char calchash[0x20];
	size_t filebufsz=0, pos, i, hashblocksize=0;
	size_t patterndata_size=0, patternmask_size=0;
	unsigned int tmpsize=0;
	unsigned int stride = 4;
	unsigned int tmpval, tmpval2;
	unsigned int baseaddr = 0;
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
		printf("--patterntype=<type> Selects the pattern-type, which must be one of the following(this option is required): sha256 or datacmp. sha256: Hash every --patternsha256size bytes in the binary, for locating the target pattern. The input bindata(sha256 hash) size must be 0x20-bytes.\n");
		printf("--patterndata=<bindata> Pattern data to use during searching the binary, see --patterntype.\n");
		printf("--patterndatamask=<bindata> Mask data to use with pattern-type datacmp. The byte-size can be less than the size of patterndata as well. The data loaded from the filebuf is &= with this mask data.\n");
		printf("--patternsha256size=0x<hexval> See --patterntype.\n");
		printf("--stride=0x<hexval> In the search loop, this is the value that the pos is increased by at the end of each interation. By default this is 0x4.\n");
		printf("--findtarget=0x<hexval> Stop searching once this number of matches were found, by default this is 0x1. When this is 0x0, this will not stop until the end of the binary is reached.\n");
		printf("--baseaddr=0x<hexval> This is the value which is added to the located offset when printing it, by default this is 0x0.\n");

		return 0;
	}

	ret = 0;

	for(argi=2; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--patterntype=", 14)==0)
		{
			if(strncmp(&argv[argi][14], "sha256", 6)==0)
			{
				patterntype = 0;
			}
			else if(strncmp(&argv[argi][14], "datacmp", 7)==0)
			{
				patterntype = 1;
			}
			else
			{
				printf("Invalid pattern-type.\n");
				ret = 5;
			}
		}

		if(strncmp(argv[argi], "--patterndata=", 14)==0)
		{
			tmpsize = 0;
			ret = load_bindata(&argv[argi][14], &patterndata, &tmpsize);
			patterndata_size = tmpsize;
		}

		if(strncmp(argv[argi], "--patterndatamask=", 18)==0)
		{
			tmpsize = 0;
			ret = load_bindata(&argv[argi][18], &patternmask, &tmpsize);
			patternmask_size = tmpsize;
		}

		if(strncmp(argv[argi], "--patternsha256size=", 20)==0)
		{
			sscanf(&argv[argi][20], "0x%x", &tmpsize);
			hashblocksize = tmpsize;
		}

		if(strncmp(argv[argi], "--stride=", 9)==0)
		{
			sscanf(&argv[argi][9], "0x%x", &stride);
		}

		if(strncmp(argv[argi], "--findtarget=", 13)==0)
		{
			sscanf(&argv[argi][13], "0x%x", &findtarget);
		}

		if(strncmp(argv[argi], "--baseaddr=", 11)==0)
		{
			sscanf(&argv[argi][11], "0x%x", &baseaddr);
		}

		if(ret!=0)break;
	}

	if(ret!=0)return ret;

	if(patterntype==-1)
	{
		printf("No pattern-type specified.\n");
		ret = 5;
	}

	if(patterntype==0)
	{
		if(patterndata_size==0)
		{
			printf("--patternsha256size must be used when pattern-type is sha256.\n");
			ret = 5;
		}

		if(patterndata_size != 0x20)
		{
			printf("Input hash size is invalid.\n");
			ret = 5;
		}
	}

	if(ret!=0)
	{
		free(patterndata);
		free(patternmask);
		return ret;
	}

	if(stat(argv[1], &filestat)==-1)
	{
		printf("Failed to stat the input binary: %s.\n", argv[1]);
		free(patterndata);
		free(patternmask);
		return 1;
	}

	filebufsz = filestat.st_size;
	filebuf = malloc(filebufsz);
	if(filebuf==NULL)
	{
		printf("Failed to alloc filebuf.\n");
		free(patterndata);
		free(patternmask);
		return 2;
	}

	fbin = fopen(argv[1], "rb");
	if(fbin==NULL)
	{
		printf("Failed to open the input binary.\n");
		free(filebuf);
		free(patterndata);
		free(patternmask);
		return 3;
	}

	if(fread(filebuf, 1, filebufsz, fbin) != filebufsz)
	{
		printf("Failed to read the input binary.\n");
		free(filebuf);
		free(patterndata);
		free(patternmask);
		fclose(fbin);
		return 4;
	}

	fclose(fbin);

	found = 0;
	ret = 0;

	for(pos=0; pos<filebufsz; pos+=stride)
	{
		tmpval = 0;

		if(patterntype==0)
		{
			if(filebufsz - pos < hashblocksize)break;

			SHA256(&filebuf[pos], hashblocksize, calchash);
			if(memcmp(patterndata, calchash, 0x20)==0)
			{
				tmpval = 1;
			}
		}
		else if(patterntype==1)
		{
			if(filebufsz - pos < patterndata_size)break;

			

			if(patternmask==NULL)
			{
				if(memcmp(patterndata, &filebuf[pos], patterndata_size)==0)
				{
					tmpval = 1;
				}
			}
			else
			{
				found2 = 1;

				for(i=0; i<patterndata_size; i++)
				{
					tmpval2 = filebuf[pos+i];
					if(i<patternmask_size)tmpval2 &= patternmask[i];

					if(tmpval2 != patterndata[i])
					{
						found2 = 0;
						break;
					}
				}

				if(found2)tmpval = 1;
			}
		}

		if(tmpval)
		{
			printf("Found the pattern at 0x%x.\n", ((unsigned int)pos) + baseaddr);
			found++;
			if(found==findtarget)break;
		}
	}

	if(!found)
	{
		printf("Failed to find the pattern.\n");
		ret = 7;
	}
	else
	{
		printf("Found 0x%x matches.\n", found);
	}

	free(filebuf);
	free(patterndata);
	free(patternmask);

	return ret;
}

