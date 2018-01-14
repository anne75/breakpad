#include "md2core_x86_64.h"


namespace md2core {


  CrashedProcessX86_64::CrashedProcessX86_64() {
    crashing_tid = -1;
    auxv = NULL;
    auxv_length = 0;
    memset(&prps, 0, sizeof(prps));
    prps.pr_sname = 'R';
    memset(&debug, 0, sizeof(debug));
    elf_arch = EM_X86_64;
  }


  void
  CrashedProcessX86_64::ParseThreadRegisters(Thread86_64* thread,
					     const MinidumpMemoryRange& range) {
    const MDRawContextAMD64* rawregs = range.GetData<MDRawContextAMD64>(0);

    thread->regs.r15 = rawregs->r15;
    thread->regs.r14 = rawregs->r14;
    thread->regs.r13 = rawregs->r13;
    thread->regs.r12 = rawregs->r12;
    thread->regs.rbp = rawregs->rbp;
    thread->regs.rbx = rawregs->rbx;
    thread->regs.r11 = rawregs->r11;
    thread->regs.r10 = rawregs->r10;
    thread->regs.r9 = rawregs->r9;
    thread->regs.r8 = rawregs->r8;
    thread->regs.rax = rawregs->rax;
    thread->regs.rcx = rawregs->rcx;
    thread->regs.rdx = rawregs->rdx;
    thread->regs.rsi = rawregs->rsi;
    thread->regs.rdi = rawregs->rdi;
    thread->regs.orig_rax = rawregs->rax;
    thread->regs.rip = rawregs->rip;
    thread->regs.cs  = rawregs->cs;
    thread->regs.eflags = rawregs->eflags;
    thread->regs.rsp = rawregs->rsp;
    thread->regs.ss = rawregs->ss;
    thread->regs.fs_base = 0;
    thread->regs.gs_base = 0;
    thread->regs.ds = rawregs->ds;
    thread->regs.es = rawregs->es;
    thread->regs.fs = rawregs->fs;
    thread->regs.gs = rawregs->gs;

    thread->fpregs.cwd = rawregs->flt_save.control_word;
    thread->fpregs.swd = rawregs->flt_save.status_word;
    thread->fpregs.ftw = rawregs->flt_save.tag_word;
    thread->fpregs.fop = rawregs->flt_save.error_opcode;
    thread->fpregs.rip = rawregs->flt_save.error_offset;
    thread->fpregs.rdp = rawregs->flt_save.data_offset;
    thread->fpregs.mxcsr = rawregs->flt_save.mx_csr;
    thread->fpregs.mxcr_mask = rawregs->flt_save.mx_csr_mask;
    memcpy(thread->fpregs.st_space, rawregs->flt_save.float_registers, 8 * 16);
    memcpy(thread->fpregs.xmm_space, rawregs->flt_save.xmm_registers, 16 * 16);
  }


  void
  CrashedProcessX86_64::ParseSystemInfo(const Options& options,
					const MinidumpMemoryRange& range,
					const MinidumpMemoryRange& full_file) {
    const MDRawSystemInfo* sysinfo = range.GetData<MDRawSystemInfo>(0);
    if (!sysinfo) {
      fprintf(stderr, "Failed to access MD_SYSTEM_INFO_STREAM\n");
      exit(1);
    }
    if (sysinfo->processor_architecture != MD_CPU_ARCHITECTURE_AMD64) {
      fprintf(stderr,
	      "This version of minidump-2-core only supports x86 (64bit)%s.\n",
	      sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_X86 ?
	      ",\nbut the minidump file is from a 32bit machine" : "");
      exit(1);
    }
// call super
    CrashedProcess<Thread86_64, prpsinfo86_64,
		   prstatus86_64, user_fpregs86_64_struct,
		   user_regs86_64_struct>::ParseSystemInfo(options, range, full_file);
  }

}
