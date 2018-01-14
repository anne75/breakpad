#ifndef MD_2_CORE_H_
#define MD_2_CORE_H_


#include <elf.h>  // ELF_AARCH is one of EM_x86_64... defined there
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cstdint> //uint..._
// siginfo
#include <signal.h>

#include <map>
#include <string>
#include <vector>

#include "common/linux/memory_mapped_file.h"
#include "common/minidump_type_helper.h"
#include "common/scoped_ptr.h"
#include "common/using_std_string.h"
#include "google_breakpad/common/breakpad_types.h"
#include "google_breakpad/common/minidump_format.h"
#include "third_party/lss/linux_syscall_support.h"
#include "tools/linux/md2core/minidump_memory_range.h"


#if __WORDSIZE == 64
  #define ELF_CLASS ELFCLASS64
#else
  #define ELF_CLASS ELFCLASS32
#endif

namespace md2core {

#define Ehdr   ElfW(Ehdr)
#define Phdr   ElfW(Phdr)
#define Shdr   ElfW(Shdr)
#define Nhdr   ElfW(Nhdr)
#define auxv_t ElfW(auxv_t)

// from readelf/binutils
#define align_power(addr, align)        \
  (((addr) + ((unsigned long) 1 << (align)) - 1) & (-((unsigned long) 1 << (align))))


  typedef struct Options {
    string minidump_path;
    bool verbose;
    int out_fd;
    bool use_filename;
    bool inc_guid;
    string so_basedir;
    string arch;
  } Options;

  bool
    writea(int fd, const void* idata, size_t length);

  using google_breakpad::MDTypeHelper;
  using google_breakpad::MemoryMappedFile;
  using google_breakpad::MinidumpMemoryRange;

  typedef MDTypeHelper<sizeof(ElfW(Addr))>::MDRawDebug MDRawDebug;
  typedef MDTypeHelper<sizeof(ElfW(Addr))>::MDRawLinkMap MDRawLinkMap;

  static const MDRVA kInvalidMDRVA = static_cast<MDRVA>(-1);

  typedef struct elf_timeval {    /* Time value with microsecond resolution    */
    long tv_sec;                  /* Seconds                                   */
    long tv_usec;                 /* Microseconds                              */
  } elf_timeval;

  typedef struct _elf_siginfo {   /* Information about signal (unused)         */
    int32_t si_signo;             /* Signal number                             */
    int32_t si_code;              /* Extra code                                */
    int32_t si_errno;             /* Errno                                     */
  } _elf_siginfo;


  struct Mapping {
  Mapping()
  : permissions(0xFFFFFFFF),
      start_address(0),
      end_address(0),
      offset(0) {
  }
    uint32_t permissions;
    uint64_t start_address, end_address, offset;
    // The name we write out to the core.
    string filename;
    string data;
  };

  struct Signature {
    char guid[40];
    string filename;
  };

//This class is template and abstract.

// T will be a thread
// P will be prpsinfo
// Prs will be prstatuts
// F will be fpregs or fpsim
// R will be user_regs

  template <typename T, typename P, typename Prs, typename F,
            typename R >
    class CrashedProcess {
  public:
 
    virtual ~CrashedProcess();
 
    virtual void
      ParseThreadRegisters(T* thread,
			   const MinidumpMemoryRange& range);
    void
      ParseThreadList(const Options& options,
		      const MinidumpMemoryRange& range,
		      const MinidumpMemoryRange& full_file);

    void
      ParseSystemInfo(const Options& options,
		      const MinidumpMemoryRange& range,
		      const MinidumpMemoryRange& full_file);
  
    void
      ParseCPUInfo(const Options& options,
		   const MinidumpMemoryRange& range);

    void
      ParseProcessStatus(const Options& options,
			 const MinidumpMemoryRange& range);

    void
      ParseLSBRelease(const Options& options,
		      const MinidumpMemoryRange& range);

    void
      ParseMaps(const Options& options,
		const MinidumpMemoryRange& range);

    void
      ParseEnvironment(const Options& options,
		       const MinidumpMemoryRange& range);

    void
      ParseAuxVector(const Options& options,
		     const MinidumpMemoryRange& range);

    void
      ParseCmdLine(const Options& options,
		   const MinidumpMemoryRange& range);

    void
      ParseDSODebugInfo(const Options& options,
			const MinidumpMemoryRange& range,
			const MinidumpMemoryRange& full_file);

    void
      ParseExceptionStream(const Options& options,
			   const MinidumpMemoryRange& range);

    bool
      WriteThread(const Options& options, const T& thread,
		  int fatal_signal);

    void
      ParseModuleStream(const Options& options,
			const MinidumpMemoryRange& range,
			const MinidumpMemoryRange& full_file);

    void
      AddDataToMapping(const string& data,
		       uintptr_t addr);

    void
      AugmentMappings(const Options& options,
		      const MinidumpMemoryRange& full_file);

    size_t
      get_filesz();

    bool
      write_prpsinfo(const Options& options, Nhdr* nhdr);

    void
      write_threads(const Options& options);

    int // ?
      write_core(const Options& options, const MinidumpMemoryRange& dump);

    std::map<uint64_t, Mapping> mappings;
    pid_t crashing_tid;
    int fatal_signal;
    // threads
    std::vector<T> threads;
    const uint8_t* auxv;
    size_t auxv_length;
    // prpsinfo
    P prps;
    // The GUID/filename from MD_MODULE_LIST_STREAM entries.
    // We gather them for merging later on into the list of maps.
    std::map<uintptr_t, Signature> signatures;
    string dynamic_data;
    MDRawDebug debug;
    std::vector<MDRawLinkMap> link_map;
    //siginfo
    siginfo_t siginfo;
    int elf_arch;

  };
}

#endif  // MD_2_CORE_H_
