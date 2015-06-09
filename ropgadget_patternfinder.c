#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/sha.h>

//Build with: gcc -o ropgadget_patternfinder ropgadget_patternfinder.c -lcrypto

int patterntype = -1;
unsigned int findtarget=1;
unsigned int stride = 4;
unsigned int baseaddr = 0;
int plainout = 0;
unsigned char *filebuf = NULL, *patterndata = NULL, *patternmask = NULL;
size_t filebufsz=0, hashblocksize=0;
size_t patterndata_size=0, patternmask_size=0;

int enable_script = 0;

char line_prefix[256];
char script_path[1024];

void hexdump(void *ptr, int buflen)//From ctrtool.
{
	unsigned char *buf = (unsigned char*)ptr;
	int i, j;

	for (i=0; i<buflen; i+=16)
	{
		printf("%06x: ", i);
		for (j=0; j<16; j++)
		{ 
			if (i+j < buflen)
			{
				printf("%02x ", buf[i+j]);
			}
			else
			{
				printf("   ");
			}
		}

		printf(" ");

		for (j=0; j<16; j++) 
		{
			if (i+j < buflen)
			{
				printf("%c", (buf[i+j] >= 0x20 && buf[i+j] <= 0x7e) ? buf[i+j] : '.');
			}
		}
		printf("\n");
	}
}

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

int parse_param(char *param, int type)
{
	int ret=0;
	unsigned int tmpsize=0;

	if(strncmp(param, "--patterntype=", 14)==0)
	{
		if(strncmp(&param[14], "sha256", 6)==0)
		{
			patterntype = 0;
		}
		else if(strncmp(&param[14], "datacmp", 7)==0)
		{
			patterntype = 1;
		}
		else
		{
			printf("Invalid pattern-type.\n");
			ret = 5;
		}
	}

	if(strncmp(param, "--patterndata=", 14)==0)
	{
		if(patterndata)
		{
			free(patterndata);
			patterndata = NULL;
		}

		tmpsize = 0;
		ret = load_bindata(&param[14], &patterndata, &tmpsize);
		patterndata_size = tmpsize;
	}

	if(strncmp(param, "--patterndatamask=", 18)==0)
	{
		if(patterndata)
		{
			free(patternmask);
			patternmask = NULL;
		}

		tmpsize = 0;
		ret = load_bindata(&param[18], &patternmask, &tmpsize);
		patternmask_size = tmpsize;
	}

	if(strncmp(param, "--patternsha256size=", 20)==0)
	{
		sscanf(&param[20], "0x%x", &tmpsize);
		hashblocksize = tmpsize;
	}

	if(strncmp(param, "--stride=", 9)==0)
	{
		sscanf(&param[9], "0x%x", &stride);
	}

	if(strncmp(param, "--findtarget=", 13)==0)
	{
		sscanf(&param[13], "0x%x", &findtarget);
	}

	if(strncmp(param, "--baseaddr=", 11)==0)
	{
		sscanf(&param[11], "0x%x", &baseaddr);
	}

	if(strncmp(param, "--plainout", 10)==0)
	{
		plainout = 1;
		if(param[10] == '=')
		{
			strncpy(line_prefix, &param[11], sizeof(line_prefix)-1);
		}
	}

	if(type==0 && strncmp(param, "--script", 8)==0)
	{
		enable_script = 1;
		if(param[8] == '=')
		{
			strncpy(script_path, &param[9], sizeof(script_path)-1);
		}
	}

	return ret;
}

int verify_params_state()
{
	int ret = 0;

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

	return ret;
}

int locate_pattern()
{
	int ret=0;
	size_t pos, i;
	unsigned int found, found2;
	unsigned int tmpval, tmpval2;

	unsigned char calchash[0x20];

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
			if(!plainout)printf("Found the pattern at ");
			printf("%s0x%x", line_prefix, ((unsigned int)pos) + baseaddr);
			if(!plainout)printf(".");
			printf("\n");
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
		if(!plainout)printf("Found 0x%x matches.\n", found);
	}

	return ret;
}

int parse_script(FILE *fscript)
{
	int pos, pos2;
	int ret=0;
	int linenum = 0;
	char *strptr, *strptr2;

	char linebuf[1024];
	char tmpbuf[1024];

	memset(linebuf, 0, sizeof(linebuf));

	while(fgets(linebuf, 1023, fscript))
	{
		linenum++;

		strptr = strchr(linebuf, '\n');
		if(strptr)*strptr = 0;

		if(strlen(linebuf)==0)continue;

		strptr = linebuf;

		if(patternmask_size)
		{
			free(patternmask);
			patternmask = NULL;
			patternmask_size=0;
		}

		while(*strptr)
		{
			if(strptr[0] == ' ')
			{
				strptr++;
				continue;
			}

			if(strptr[0] == '"' || strptr[0] == '\'')
			{
				strptr++;

				memset(tmpbuf, 0, sizeof(tmpbuf));

				for(pos=0; pos<sizeof(tmpbuf)-1; pos++)
				{
					if(strptr[pos]==0 || strptr[pos] == '\'' || strptr[pos] == '"')break;

					tmpbuf[pos] = strptr[pos];
				}

				if(strptr[pos] == '\'' || strptr[pos] == '"')strptr++;
				strptr+= pos;
			}
			else
			{
				memset(tmpbuf, 0, sizeof(tmpbuf));

				for(pos=0; pos<sizeof(tmpbuf)-1; pos++)
				{
					if(strptr[pos]==0 || strptr[pos] == ' ')break;

					tmpbuf[pos] = strptr[pos];
				}

				if(strptr[pos] == ' ')strptr++;
				strptr+= pos;
			}

			ret = parse_param(tmpbuf, 1);
			if(ret!=0)
			{
				printf("Line#: %d\n", linenum);
				return ret;
			}
		}

		ret = verify_params_state();
		if(ret!=0)
		{
			printf("Line#: %d\n", linenum);
			return ret;
		}

		ret = locate_pattern();
		if(ret!=0)
		{
			printf("Line#: %d\n", linenum);
			return ret;
		}
	}

	return ret;
}

int main(int argc, char **argv)
{
	int argi;
	int ret;
	struct stat filestat;
	FILE *fbin, *fscript;

	if(argc<3)
	{
		printf("ropgadget_patternfinder by yellows8.\n");
		printf("Locates the offset/address of the specified pattern in the input binary. This tool is mainly intended for locating ROP-gadgets, but it could be used for other purposes as well.\n");
		printf("<bindata> below can be either hex with any byte-length(unless specified otherwise), or '@' followed by a file-path to load the data from.\n");
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
		printf("--plainout[=<prefix text>] Only print the located offset/address, unless an error occurs. If '=<text>' is specified, print that before printing the located offset/address.\n");
		printf("--script=<path> Specifies a script from which to load params from(identical to the cmd-line params), each line is for a different pattern to search for. Each param applies to the current line, and all the lines after that until that param gets specified on another line again. When '=<path>' isn't specified, the script is read from stdin. When this --script option is used, all input-param state is reset to the defaults, except for --patterntype, --baseaddr, and --findtarget. When beginning processing each line, the --patterndatamask is reset to the default before parsing the params each time.\n");

		return 0;
	}

	ret = 0;

	memset(line_prefix, 0, sizeof(line_prefix));
	memset(script_path, 0, sizeof(script_path));

	for(argi=2; argi<argc; argi++)
	{
		ret = parse_param(argv[argi], 0);

		if(ret!=0)break;
	}

	if(ret!=0)return ret;

	if(!enable_script)
	{
		ret = verify_params_state();

		if(ret!=0)
		{
			free(patterndata);
			free(patternmask);
			return ret;
		}
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

	if(enable_script)
	{
		free(patterndata);
		free(patternmask);
		patterndata = NULL;
		patternmask = NULL;
		patterndata_size=0;
		patternmask_size=0;

		hashblocksize = 0;

		stride = 4;
		plainout = 0;
		memset(line_prefix, 0, sizeof(line_prefix));

		if(script_path[0])
		{
			fscript = fopen(script_path, "r");
			if(fscript==NULL)
			{
				printf("Failed to open script.\n");
				free(filebuf);
				return 1;
			}
		}
		else
		{
			fscript = stdin;
		}
	}

	if(!enable_script)
	{
		ret = locate_pattern();
	}
	else
	{
		ret = parse_script(fscript);
		if(script_path[0])fclose(fscript);
	}

	free(filebuf);
	free(patterndata);
	free(patternmask);

	return ret;
}

