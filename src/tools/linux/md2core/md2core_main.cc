// #include <elf.h>
// #include <errno.h>
// #include <link.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// #include <unistd.h>

// #include <map>
// #include <string>
// #include <vector>


// #include "common/linux/memory_mapped_file.h"
// #include "common/minidump_type_helper.h"
// #include "common/scoped_ptr.h"
// #include "common/using_std_string.h"
// #include "google_breakpad/common/breakpad_types.h"
// #include "google_breakpad/common/minidump_format.h"
// #include "third_party/lss/linux_syscall_support.h"
// #include "tools/linux/md2core/minidump_memory_range.h"

// // siginfo
// #include <signal.h>

#include <memory>  // unique_ptr

#include "md2core.h"
#include "md2core_x86_64.h"
#include "md2core_aarch64.h"



namespace md2core {

  using google_breakpad::MDTypeHelper;
  using google_breakpad::MemoryMappedFile;
  using google_breakpad::MinidumpMemoryRange;

  

  static void
    Usage(int argc, const char* argv[]) {
    fprintf(stderr,
	    "Usage: %s [options] <minidump file>\n"
	    "\n"
	    "Convert a minidump file into a core file (often for use by gdb).\n"
	    "\n"
	    "The shared library list will by default have filenames as the runtime expects.\n"
	    "There are many flags to control the output names though to make it easier to\n"
	    "integrate with your debug environment (e.g. gdb).\n"
	    " Default:    /lib64/libpthread.so.0\n"
	    " -f:         /lib64/libpthread-2.19.so\n"
	    " -i:         /lib64/<module id>-libpthread.so.0\n"
	    " -f -i:      /lib64/<module id>-libpthread-2.19.so\n"
	    " -S /foo/:   /foo/libpthread.so.0\n"
	    "\n"
	    "Options:\n"
	    "  -v         Enable verbose output\n"
	    "  -o <file>  Write coredump to specified file (otherwise use stdout).\n"
	    "  -f         Use the filename rather than the soname in the sharedlib list.\n"
	    "             The soname is what the runtime system uses, but the filename is\n"
	    "             how it's stored on disk.\n"
	    "  -i         Prefix sharedlib names with ID (when available).  This makes it\n"
	    "             easier to have a single directory full of symbols.\n"
	    "  -S <dir>   Set soname base directory.  This will force all debug/symbol\n"
	    "             lookups to be done in this directory rather than the filesystem\n"
	    "             layout as it exists in the crashing image.  This path should end\n"
	    "             with a slash if it's a directory.  e.g. /var/lib/breakpad/\n"
	    "  -a         Architecture, either 86_64 or aarch64\n"
	    "", basename(argv[0]));
  }

  static void
    SetupOptions(int argc, const char* argv[], Options* options) {
    extern int optind;
    int ch;
    const char* output_file = NULL;

    // Initialize the options struct as needed.
    options->verbose = false;
    options->use_filename = false;
    options->inc_guid = false;

    while ((ch = getopt(argc, (char * const *)argv, "fhio:S:va:")) != -1) {
      switch (ch) {
      case 'h':
        Usage(argc, argv);
        exit(0);
        break;
      case '?':
        Usage(argc, argv);
        exit(1);
        break;
      case 'f':
        options->use_filename = true;
        break;
      case 'i':
        options->inc_guid = true;
        break;
      case 'o':
        output_file = optarg;
        break;
      case 'S':
        options->so_basedir = optarg;
        break;
      case 'v':
        options->verbose = true;
      case 'a':
	options->arch = optarg;
        break;
      }
    }

    if ((argc - optind) != 1) {
      fprintf(stderr, "%s: Missing minidump file\n", argv[0]);
      Usage(argc, argv);
      exit(1);
    }

    if (output_file == NULL || !strcmp(output_file, "-")) {
      options->out_fd = STDOUT_FILENO;
    } else {
      options->out_fd = open(output_file, O_WRONLY|O_CREAT|O_TRUNC, 0664);
      if (options->out_fd == -1) {
	fprintf(stderr, "%s: could not open output %s: %s\n", argv[0],
		output_file, strerror(errno));
	exit(1);
      }
    }

    options->minidump_path = argv[optind];
  }


  int
    main(int argc, const char* argv[]) {
    Options options;

    SetupOptions(argc, argv, &options);

    MemoryMappedFile mapped_file(options.minidump_path.c_str(), 0);
    if (!mapped_file.data()) {
      fprintf(stderr, "Failed to mmap dump file: %s: %s\n",
	      options.minidump_path.c_str(), strerror(errno));
      return 1;
    }

    MinidumpMemoryRange dump(mapped_file.data(), mapped_file.size());

    if (!options.arch.compare("86_64")) {
      // create relevant object and call member function
      CrashedProcessX86_64 crashinfo = CrashedProcessX86_64();
       return crashinfo.write_core(options, dump);
    } else if (!options.arch.compare("aarch64")) {
      // idem
      CrashedProcessAarch64 c = CrashedProcessAarch64();
      return c.write_core(options, dump);
    } else {
      fprintf(stderr, "Option %s is neither 86_64 nor aarch64.\n",
	      options.arch.c_str());
      exit(1);
    }

  }

}
