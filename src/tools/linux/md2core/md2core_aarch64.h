#ifndef MD_2_CORE_AARCH_64_H_
#define MD_2_CORE_AARCH_64_H_

#include "md2core.h"

namespace md2core {


  typedef struct prpsinfoaarch64 {       /* Information about process                 */
    unsigned char  pr_state;      /* Numeric process state                     */
    char           pr_sname;      /* Char for pr_state                         */
    unsigned char  pr_zomb;       /* Zombie                                    */
    signed char    pr_nice;       /* Nice val                                  */
    unsigned long  pr_flag;       /* Flags                                     */
    uint16_t       pr_uid;        /* User ID                                   */
    uint16_t       pr_gid;        /* Group ID                                  */
    pid_t          pr_pid;        /* Process ID                                */
    pid_t          pr_ppid;       /* Parent's process ID                       */
    pid_t          pr_pgrp;       /* Group ID                                  */
    pid_t          pr_sid;        /* Session ID                                */
    char           pr_fname[16];  /* Filename of executable                    */
    char           pr_psargs[80]; /* Initial part of arg list                  */
  } prpsinfoaarch64;

  typedef struct user_fpsimd_struct {
    __uint128_t vregs[32];
    uint32_t fpsr;
    uint32_t fpcr;
  } user_fpsimd_struct;

    typedef struct user_regsaarch64_struct {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
  } user_regsaarch64_struct;

  struct Threadaarch64 {
    pid_t tid;
    user_regsaarch64_struct regs;
    user_fpsimd_struct fpregs;
    uintptr_t stack_addr;
    const uint8_t* stack;
    size_t stack_length;
  };

  typedef struct prstatusaarch64 {       /* Information about thread; includes CPU reg*/
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
    user_regsaarch64_struct pr_reg;      /* CPU registers                             */
    uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
  } prstatusaarch64;


  class CrashedProcessAarch64: public CrashedProcess<Threadaarch64,
                                             prpsinfoaarch64,
                                             prstatusaarch64,
                                             user_fpsimd_struct,
                                             user_regsaarch64_struct> {

  public:
    CrashedProcessAarch64();
    virtual ~CrashedProcessAarch64();

    void
      ParseThreadRegisters(Threadaarch64* thread,
			   const MinidumpMemoryRange& range);

    void
      ParseSystemInfo(const Options& options,
		      const MinidumpMemoryRange& range,
		      const MinidumpMemoryRange& full_file);

    void
      write_threads(const Options& options);

  };
}

#endif  // MD_2_CORE_AARCH64_H_
