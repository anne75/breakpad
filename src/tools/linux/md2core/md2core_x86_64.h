#ifndef MD_2_CORE_X86_64_H_
#define MD_2_CORE_x86_64_H_

#include "md2core.h"

namespace md2core {

  typedef struct prpsinfo86_64 {       /* Information about process                 */
    unsigned char  pr_state;      /* Numeric process state                     */
    char           pr_sname;      /* Char for pr_state                         */
    unsigned char  pr_zomb;       /* Zombie                                    */
    signed char    pr_nice;       /* Nice val                                  */
    unsigned long  pr_flag;       /* Flags                                     */
    uint32_t       pr_uid;        /* User ID                                   */
    uint32_t       pr_gid;        /* Group ID                                  */
    pid_t          pr_pid;        /* Process ID                                */
    pid_t          pr_ppid;       /* Parent's process ID                       */
    pid_t          pr_pgrp;       /* Group ID                                  */
    pid_t          pr_sid;        /* Session ID                                */
    char           pr_fname[16];  /* Filename of executable                    */
    char           pr_psargs[80]; /* Initial part of arg list                  */
  } prpsinfo86_64;

// from sys/user.h
  typedef struct user_fpregs86_64_struct
  {
    unsigned short int    cwd;
    unsigned short int    swd;
    unsigned short int    ftw;
    unsigned short int    fop;
    __extension__ unsigned long long int rip;
    __extension__ unsigned long long int rdp;
    unsigned int          mxcsr;
    unsigned int          mxcr_mask;
    unsigned int          st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
    unsigned int          xmm_space[64];  /* 16*16 bytes for each XMM-reg = 256 bytes */
    unsigned int          padding[24];
  } user_fpregs86_64_struct;

  typedef struct user_regs86_64_struct
  {
    __extension__ unsigned long long int r15;
    __extension__ unsigned long long int r14;
    __extension__ unsigned long long int r13;
    __extension__ unsigned long long int r12;
    __extension__ unsigned long long int rbp;
    __extension__ unsigned long long int rbx;
    __extension__ unsigned long long int r11;
    __extension__ unsigned long long int r10;
    __extension__ unsigned long long int r9;
    __extension__ unsigned long long int r8;
    __extension__ unsigned long long int rax;
    __extension__ unsigned long long int rcx;
    __extension__ unsigned long long int rdx;
    __extension__ unsigned long long int rsi;
    __extension__ unsigned long long int rdi;
    __extension__ unsigned long long int orig_rax;
    __extension__ unsigned long long int rip;
    __extension__ unsigned long long int cs;
    __extension__ unsigned long long int eflags;
    __extension__ unsigned long long int rsp;
    __extension__ unsigned long long int ss;
    __extension__ unsigned long long int fs_base;
    __extension__ unsigned long long int gs_base;
    __extension__ unsigned long long int ds;
    __extension__ unsigned long long int es;
    __extension__ unsigned long long int fs;
    __extension__ unsigned long long int gs;
  } user_regs86_64_struct;


  typedef struct prstatus86_64 {       /* Information about thread; includes CPU reg*/
    _elf_siginfo   pr_info;       /* Info associated with signal               */
    uint16_t       pr_cursig;     /* Current signal                            */
    unsigned long  pr_sigpend;    /* Set of pending signals                    */
    unsigned long  pr_sighold;    /* Set of held signals                       */
    pid_t          pr_pid;        /* Process ID                                */
    pid_t          pr_ppid;       /* Parent's process ID                       */
    pid_t          pr_pgrp;       /* Group ID                                  */
    pid_t          pr_sid;        /* Session ID                                */
    elf_timeval    pr_utime;      /* User time                                 */
    elf_timeval    pr_stime;      /* System time                               */
    elf_timeval    pr_cutime;     /* Cumulative user time                      */
    elf_timeval    pr_cstime;     /* Cumulative system time                    */
// that is function of architecture
    user_regs86_64_struct pr_reg;      /* CPU registers                        */
    uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
  } prstatus86_64;

  struct Thread86_64 {
    pid_t tid;
    user_regs86_64_struct regs;
    user_fpregs86_64_struct fpregs;
    uintptr_t stack_addr;
    const uint8_t* stack;
    size_t stack_length;
  };


// T will be a thread
// P will be prpsinfo
// Prs will be prstatuts
// F will be fpregs or fpsim
// R will be user_regs

  class CrashedProcessX86_64: public CrashedProcess<Thread86_64,
                                             prpsinfo86_64,
                                             prstatus86_64,
                                             user_fpregs86_64_struct,
                                             user_regs86_64_struct> {

  public:
    CrashedProcessX86_64();

    void
      ParseThreadRegisters(Thread86_64* thread,
			   const MinidumpMemoryRange& range);

    void
      ParseSystemInfo(const Options& options,
		      const MinidumpMemoryRange& range,
		      const MinidumpMemoryRange& full_file);

    void
      write_threads(const Options& options);
  };

}

#endif // MD_2_CORE_x86_64_H_
