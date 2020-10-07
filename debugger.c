/*************************************************************************
	> File Name: debugger.c
	> Author: 
	> Mail: 
	> Created Time: 2020年10月06日 星期二 02时18分18秒
 ************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
 
#define BKPT   0xCC
#define BKPT_MASK   0xFFFFFFFFFFFFFF00
 
#define FILEPATH_LEN 100
#define SYMBOL_NAME_LEN 30
#define BUF_LEN 200

char filename[FILEPATH_LEN];
FILE *fp;
int child_pid;
typedef struct{
    long addr;
    long original_code;
    char name[SYMBOL_NAME_LEN + 1];
}Breakpoint;
Breakpoint *breakpoints;
int bp_count;
void parse_elf_file()
{
    Elf64_Ehdr elf_header;
    Elf64_Shdr section_header;
    fp = fopen(filename,"r");
    if(!fp)
    {
        printf("Failed to open ELF file\n");
        exit(-1);
    }
    fread(&elf_header,1,sizeof(elf_header),fp);
    fseek(fp,elf_header.e_shoff,SEEK_SET);
    for(int i=0;i<elf_header.e_shnum;i++)
    {
        fread(&section_header,1,sizeof(section_header),fp);
        if(section_header.sh_type==SHT_SYMTAB)
        {
            Elf64_Shdr strtab_header;
            long strtab_hdr_offset = elf_header.e_shoff + section_header.sh_link*sizeof(section_header);
            fseek(fp,strtab_hdr_offset,SEEK_SET);
            fread(&strtab_header,1,sizeof(strtab_header),fp);
            fseek(fp,section_header.sh_offset,SEEK_SET);
            int entries = section_header.sh_size/section_header.sh_entsize;
            breakpoints = malloc(entries*sizeof(Breakpoint));
            for(i=0;i<entries;i++)
            {
                Elf64_Sym symbol;
                fread(&symbol,1,sizeof(symbol),fp);
                if(ELF64_ST_TYPE(symbol.st_info)==STT_FUNC && symbol.st_name!=0 && symbol.st_value != 0)
                {
                    long pos = ftell(fp);
                    fseek(fp,strtab_header.sh_offset+symbol.st_name,SEEK_SET);
                    printf("%ld\n",symbol.st_value);
                    breakpoints[bp_count].addr = symbol.st_value;
                    fread(breakpoints[bp_count].name,SYMBOL_NAME_LEN,sizeof(char),fp);
                    fseek(fp,pos,SEEK_SET);
                    //printf("%ld\n",breakpoints[bp_count].addr);
                    bp_count++;
                }
            }
        }
    }
}
void insert_brakepoints()
{
    for(int i=0;i<bp_count;i++)
    {
        breakpoints[i].original_code = ptrace(PTRACE_PEEKTEXT,child_pid,(void *)breakpoints[i].addr,0);
        ptrace(PTRACE_POKETEXT,child_pid,(void *)breakpoints[i].addr,(breakpoints[i].original_code&BKPT_MASK)|BKPT);
    }
}
void prepare_breakpoints()
{
    parse_elf_file();
    insert_brakepoints();
}
int get_bp_id(long addr)
{
    for(int i=0;i<bp_count;++i)
    {
        if(breakpoints[i].addr == addr)
        {
            return i;
        }
    }
    return -1;
}
void trace()
{
    int status;
    ptrace(PTRACE_CONT,child_pid,0,0);
    printf("Tracing started\n===\n\n");
    while(1)
    {
        waitpid(child_pid,&status,0);
        if(WIFEXITED(status))
        {
            printf("Child finished\n");
            return;
        }
        if(WIFSTOPPED(status))
        {
            if(WSTOPSIG(status)==SIGTRAP)
            {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS,child_pid,0,&regs);
                int id = get_bp_id(regs.rip-1);
                if(id==-1)
                {
                    printf("Unexpected SIGTRAP %llx\n",regs.rip);
                    return;
                }
                else
                {
                    printf("%s(),\n",breakpoints[id].name);
                    regs.rip = breakpoints[id].addr;
                    ptrace(PTRACE_SETREGS,child_pid,0,&regs);
                    ptrace(PTRACE_POKETEXT,child_pid,(void *)breakpoints[id].addr,breakpoints[id].original_code);
                    ptrace(PTRACE_SINGLESTEP,child_pid,0,0);
                    wait(NULL);
                    ptrace(PTRACE_POKETEXT,child_pid,(void *)breakpoints[id].addr,(breakpoints[id].original_code&BKPT_MASK)|BKPT);
                }
            }
            if((status>>16)&0xffff == PTRACE_EVENT_EXIT)
            {
                printf("Child finished222\n");
                return;
            }
        }
        ptrace(PTRACE_CONT,child_pid,0,0);
    }
}

int main(int argc,char *argv[])
{
    if(argc<2)
    {
        printf("Usage: tracer path\n");
        return -1;
    }
    strncpy(filename,argv[1],FILEPATH_LEN);
    child_pid=fork();
    if(child_pid==0)
    {
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execl(argv[1],argv[1],NULL);
        printf("Failed to execl!!!\n");
        exit(-1);
    }
    else
    {
        printf("PID %d\n",child_pid);
        wait(NULL);
        prepare_breakpoints();
        trace();
        free(breakpoints);
    }
    return 0;
}






