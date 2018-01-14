#include "md2core.h"


namespace md2core {

  // Write all of the given buffer, handling short writes and EINTR. Return true
// iff successful.
  bool
  writea(int fd, const void* idata, size_t length) {
    const uint8_t* data = (const uint8_t*) idata;
    
    size_t done = 0;
    while (done < length) {
      ssize_t r;
      do {
	r = write(fd, data + done, length - done);
      } while (r == -1 && errno == EINTR);

      if (r < 1)
	return false;
      done += r;
    }

    return true;
  }

  /* Dynamically determines the byte sex of the system. Returns non-zero
 * for big-endian machines.
 */
  static inline int sex() {
    int probe = 1;
    return !*(char *)&probe;
  }


  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseThreadList(const Options& options,
						   const MinidumpMemoryRange& range,
						   const MinidumpMemoryRange& full_file) {
    const uint32_t num_threads = *range.GetData<uint32_t>(0);
    if (options.verbose) {
      fprintf(stderr,
	      "MD_THREAD_LIST_STREAM:\n"
	      "Found %d threads\n"
	      "\n\n",
	      num_threads);
    }
    for (unsigned i = 0; i < num_threads; ++i) {
      T thread;
      memset(&thread, 0, sizeof(thread));
      const MDRawThread* rawthread =
        range.GetArrayElement<MDRawThread>(sizeof(uint32_t), i);
      thread.tid = rawthread->thread_id;
      thread.stack_addr = rawthread->stack.start_of_memory_range;
      MinidumpMemoryRange stack_range =
        full_file.Subrange(rawthread->stack.memory);
    thread.stack = stack_range.data();
    thread.stack_length = rawthread->stack.memory.data_size;
    
    ParseThreadRegisters(&thread,
                         full_file.Subrange(rawthread->thread_context));

    threads.push_back(thread);
    }
  }

// only place sysinfo is used. Not inside core
  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseSystemInfo(const Options& options,
				  const MinidumpMemoryRange& range,
				  const MinidumpMemoryRange& full_file) {
    const MDRawSystemInfo* sysinfo = range.GetData<MDRawSystemInfo>(0);
    if (!sysinfo) {
      fprintf(stderr, "Failed to access MD_SYSTEM_INFO_STREAM\n");
      exit(1);
    }
    if (options.verbose) {
      fprintf(stderr,
	      "MD_SYSTEM_INFO_STREAM:\n"
	      "Architecture: %s\n"
	      "Number of processors: %d\n"
	      "Processor level: %d\n"
	      "Processor model: %d\n"
	      "Processor stepping: %d\n",
	      sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_X86
	      ? "i386"
	      : sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_AMD64
	      ? "x86-64"
	      : sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_ARM
	      ? "ARM"
	      : sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_MIPS
	      ? "MIPS"
	      : sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_MIPS64
	      ? "MIPS64"
	      : "???",
	      sysinfo->number_of_processors,
	      sysinfo->processor_level,
	      sysinfo->processor_revision >> 8,
	      sysinfo->processor_revision & 0xFF);
      if (sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_X86 ||
	  sysinfo->processor_architecture == MD_CPU_ARCHITECTURE_AMD64) {
	fputs("Vendor id: ", stderr);
	const char *nul =
	  (const char *)memchr(sysinfo->cpu.x86_cpu_info.vendor_id, 0,
			       sizeof(sysinfo->cpu.x86_cpu_info.vendor_id));
	fwrite(sysinfo->cpu.x86_cpu_info.vendor_id,
	       nul ? nul - (const char *)&sysinfo->cpu.x86_cpu_info.vendor_id[0]
	       : sizeof(sysinfo->cpu.x86_cpu_info.vendor_id), 1, stderr);
	fputs("\n", stderr);
      }
      fprintf(stderr, "OS: %s\n",
	      full_file.GetAsciiMDString(sysinfo->csd_version_rva).c_str());
      fputs("\n\n", stderr);
    }
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseProcessStatus(const Options& options,
				     const MinidumpMemoryRange& range) {
    if (options.verbose) {
      fputs("MD_LINUX_PROC_STATUS:\n", stderr);
      fwrite(range.data(), range.length(), 1, stderr);
      fputs("\n\n", stderr);
    }
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseLSBRelease(const Options& options,
		  const MinidumpMemoryRange& range) {
    if (options.verbose) {
      fputs("MD_LINUX_LSB_RELEASE:\n", stderr);
      fwrite(range.data(), range.length(), 1, stderr);
      fputs("\n\n", stderr);
    }
  }

// ANNE create the arrays for NT_FILE here ?and make them crasheprocess attr
// mappings are augmented elsewhere, the question is,
// does NT_FILE need to be augmented as well?
  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseMaps(const Options& options,
			    const MinidumpMemoryRange& range) {
    if (options.verbose) {
      fputs("MD_LINUX_MAPS:\n", stderr);
      fwrite(range.data(), range.length(), 1, stderr);
    }
    for (const uint8_t* ptr = range.data();
	 ptr < range.data() + range.length();) {
      const uint8_t* eol = (uint8_t*)memchr(ptr, '\n',
					    range.data() + range.length() - ptr);
      string line((const char*)ptr,
		  eol ? eol - ptr : range.data() + range.length() - ptr);
      ptr = eol ? eol + 1 : range.data() + range.length();
      unsigned long long start, stop, offset;
      char* permissions = NULL;
      char* filename = NULL;
      sscanf(line.c_str(), "%llx-%llx %m[-rwxp] %llx %*[:0-9a-f] %*d %ms",
	     &start, &stop, &permissions, &offset, &filename);
      if (filename && *filename == '/') {
	Mapping mapping;
	mapping.permissions = 0;
	if (strchr(permissions, 'r')) {
	  mapping.permissions |= PF_R;
	}
	if (strchr(permissions, 'w')) {
	  mapping.permissions |= PF_W;
	}
	if (strchr(permissions, 'x')) {
	  mapping.permissions |= PF_X;
	}
	mapping.start_address = start;
	mapping.end_address = stop;
	mapping.offset = offset;
	if (filename) {
	  mapping.filename = filename;
	}
	mappings[mapping.start_address] = mapping;
      }
      free(permissions);
      free(filename);
    }
    if (options.verbose) {
      fputs("\n\n\n", stderr);
    }
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseEnvironment(const Options& options,
				   const MinidumpMemoryRange& range) {
    if (options.verbose) {
      fputs("MD_LINUX_ENVIRON:\n", stderr);
      char* env = new char[range.length()];
      memcpy(env, range.data(), range.length());
      int nul_count = 0;
      for (char *ptr = env;;) {
	ptr = (char *)memchr(ptr, '\000', range.length() - (ptr - env));
	if (!ptr) {
	  break;
	}
	if (ptr > env && ptr[-1] == '\n') {
	  if (++nul_count > 5) {
	    // Some versions of Chrome try to rewrite the process' command line
	    // in a way that causes the environment to be corrupted. Afterwards,
	    // part of the environment will contain the trailing bit of the
	    // command line. The rest of the environment will be filled with
	    // NUL bytes.
	    // We detect this corruption by counting the number of consecutive
	    // NUL bytes. Normally, we would not expect any consecutive NUL
	    // bytes. But we are conservative and only suppress printing of
	    // the environment if we see at least five consecutive NULs.
	    fputs("Environment has been corrupted; no data available", stderr);
	    goto env_corrupted;
	  }
	} else {
	  nul_count = 0;
	}
	*ptr = '\n';
      }
      fwrite(env, range.length(), 1, stderr);
    env_corrupted:
      delete[] env;
      fputs("\n\n\n", stderr);
    }
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseAuxVector(const Options& options,
				 const MinidumpMemoryRange& range) {
    // Some versions of Chrome erroneously used the MD_LINUX_AUXV stream value
    // when dumping /proc/$x/maps
    if (range.length() > 17) {
      // The AUXV vector contains binary data, whereas the maps always begin
      // with an 8+ digit hex address followed by a hyphen and another 8+ digit
      // address.
      char addresses[18];
      memcpy(addresses, range.data(), 17);
      addresses[17] = '\000';
      if (strspn(addresses, "0123456789abcdef-") == 17) {
	ParseMaps(options, range);
	return;
      }
    }

    auxv = range.data();
    auxv_length = range.length();
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseCmdLine(const Options& options,
			       const MinidumpMemoryRange& range) {
    // The command line is supposed to use NUL bytes to separate arguments.
    // As Chrome rewrites its own command line and (incorrectly) substitutes
    // spaces, this is often not the case in our minidump files.
    const char* cmdline = (const char*) range.data();
    if (options.verbose) {
      fputs("MD_LINUX_CMD_LINE:\n", stderr);
      unsigned i = 0;
      for (; i < range.length() && cmdline[i] && cmdline[i] != ' '; ++i) { }
      fputs("argv[0] = \"", stderr);
      fwrite(cmdline, i, 1, stderr);
      fputs("\"\n", stderr);
      for (unsigned j = ++i, argc = 1; j < range.length(); ++j) {
	if (!cmdline[j] || cmdline[j] == ' ') {
	  fprintf(stderr, "argv[%d] = \"", argc++);
	  fwrite(cmdline + i, j - i, 1, stderr);
	  fputs("\"\n", stderr);
	  i = j + 1;
	}
      }
      fputs("\n\n", stderr);
    }
    const char *binary_name = cmdline;
    for (size_t i = 0; i < range.length(); ++i) {
      if (cmdline[i] == '/') {
	binary_name = cmdline + i + 1;
      } else if (cmdline[i] == 0 || cmdline[i] == ' ') {
	static const size_t fname_len = sizeof(prps.pr_fname) - 1;
	static const size_t args_len = sizeof(prps.pr_psargs) - 1;
	memset(prps.pr_fname, 0, fname_len + 1);
	memset(prps.pr_psargs, 0, args_len + 1);
	unsigned len = cmdline + i - binary_name;
	memcpy(prps.pr_fname, binary_name,
	       len > fname_len ? fname_len : len);

	len = range.length() > args_len ? args_len : range.length();
	memcpy(prps.pr_psargs, cmdline, len);
	for (unsigned j = 0; j < len; ++j) {
	  if (prps.pr_psargs[j] == 0)
	    prps.pr_psargs[j] = ' ';
	}
	break;
      }
    }
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseDSODebugInfo(const Options& options,
				    const MinidumpMemoryRange& range,
				    const MinidumpMemoryRange& full_file) {
    const MDRawDebug* debug = range.GetData<MDRawDebug>(0);
    if (!debug) {
      return;
    }
    if (options.verbose) {
      fprintf(stderr,
	      "MD_LINUX_DSO_DEBUG:\n"
	      "Version: %d\n"
	      "Number of DSOs: %d\n"
	      "Brk handler: 0x%" PRIx64 "\n"
	      "Dynamic loader at: 0x%" PRIx64 "\n"
	      "_DYNAMIC: 0x%" PRIx64 "\n",
	      debug->version,
	      debug->dso_count,
	      static_cast<uint64_t>(debug->brk),
	      static_cast<uint64_t>(debug->ldbase),
	      static_cast<uint64_t>(debug->dynamic));
    }
    debug = *debug;
    if (range.length() > sizeof(MDRawDebug)) {
      char* dynamic = (char*)range.data() + sizeof(MDRawDebug);
      dynamic_data.assign(dynamic,
			  range.length() - sizeof(MDRawDebug));
    }
    if (debug->map != kInvalidMDRVA) {
      for (unsigned int i = 0; i < debug->dso_count; ++i) {
	const MDRawLinkMap* link_m =
	  full_file.GetArrayElement<MDRawLinkMap>(debug->map, i);
	if (link_m) {
	  if (options.verbose) {
	    fprintf(stderr,
		    "#%03d: %" PRIx64 ", %" PRIx64 ", \"%s\"\n",
		    i, static_cast<uint64_t>(link_m->addr),
		    static_cast<uint64_t>(link_m->ld),
		    full_file.GetAsciiMDString(link_m->name).c_str());
	  }
	  link_map.push_back(*link_m);
	}
      }
    }
    if (options.verbose) {
      fputs("\n\n", stderr);
    }
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseExceptionStream(const Options& options,
				       const MinidumpMemoryRange& range) {
    const MDRawExceptionStream* exp = range.GetData<MDRawExceptionStream>(0);
    crashing_tid = exp->thread_id;
    fatal_signal = (int) exp->exception_record.exception_code;

    //siginfo
    int sig_nb = (int) exp->exception_record.exception_code;
    memset(&(siginfo), 0, sizeof(siginfo_t));
    siginfo.si_signo = sig_nb;
    siginfo.si_code = SI_KERNEL; // try non zero, so readelf prints si_addr
    siginfo.si_addr = reinterpret_cast<void *>(exp->exception_record.exception_address);
  }

  template<class T, class P, class Prs, class F, class R>
  bool
  CrashedProcess<T, P, Prs, F, R>::WriteThread(const Options& options, const T& thread,
			      int fatal_signal) {
    Prs pr;
    memset(&pr, 0, sizeof(pr));

    pr.pr_info.si_signo = fatal_signal;
    //siginfo: extend to thread, not quite right, does it give reason of core
    //pr.pr_info.si_code = fatal_signal;
    pr.pr_cursig = fatal_signal; // in charge of giving reason for core
    pr.pr_pid = thread.tid;
    memcpy(&pr.pr_reg, &thread.regs, sizeof(R));

    Nhdr nhdr;
    memset(&nhdr, 0, sizeof(nhdr));
    nhdr.n_namesz = 5;
    nhdr.n_descsz = sizeof(struct prstatus);
    nhdr.n_type = NT_PRSTATUS;
    if (!writea(options.out_fd, &nhdr, sizeof(nhdr)) ||
	!writea(options.out_fd, "CORE\0\0\0\0", 8) ||
	!writea(options.out_fd, &pr, sizeof(Prs))) {
      return false;
    }

    nhdr.n_descsz = sizeof(F);
    nhdr.n_type = NT_FPREGSET;
    if (!writea(options.out_fd, &nhdr, sizeof(nhdr)) ||
	!writea(options.out_fd, "CORE\0\0\0\0", 8) ||
	!writea(options.out_fd, &thread.fpregs, sizeof(F))) {
      return false;
    }

    return true;
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::ParseModuleStream(const Options& options,
				    const MinidumpMemoryRange& range,
				    const MinidumpMemoryRange& full_file) {
    if (options.verbose) {
      fputs("MD_MODULE_LIST_STREAM:\n", stderr);
    }
    const uint32_t num_mappings = *range.GetData<uint32_t>(0);
    for (unsigned i = 0; i < num_mappings; ++i) {
      Mapping mapping;
      const MDRawModule* rawmodule = reinterpret_cast<const MDRawModule*>(
	range.GetArrayElement(sizeof(uint32_t), MD_MODULE_SIZE, i));
      mapping.start_address = rawmodule->base_of_image;
      mapping.end_address = rawmodule->size_of_image + rawmodule->base_of_image;

      if (mappings.find(mapping.start_address) ==
	  mappings.end()) {
	// We prefer data from MD_LINUX_MAPS over MD_MODULE_LIST_STREAM, as
	// the former is a strict superset of the latter.
	mappings[mapping.start_address] = mapping;
      }

      const MDCVInfoPDB70* record = reinterpret_cast<const MDCVInfoPDB70*>(
	full_file.GetData(rawmodule->cv_record.rva, MDCVInfoPDB70_minsize));
      char guid[40];
      sprintf(guid, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
	      record->signature.data1, record->signature.data2,
	      record->signature.data3,
	      record->signature.data4[0], record->signature.data4[1],
	      record->signature.data4[2], record->signature.data4[3],
	      record->signature.data4[4], record->signature.data4[5],
	      record->signature.data4[6], record->signature.data4[7]);

      string filename = full_file.GetAsciiMDString(rawmodule->module_name_rva);

      Signature signature;
      strcpy(signature.guid, guid);
      signature.filename = filename;
      signatures[rawmodule->base_of_image] = signature;

      if (options.verbose) {
	fprintf(stderr, "0x%" PRIx64 "-0x%" PRIx64 ", ChkSum: 0x%08X, GUID: %s, "
		" \"%s\"\n",
		rawmodule->base_of_image,
		rawmodule->base_of_image + rawmodule->size_of_image,
		rawmodule->checksum, guid, filename.c_str());
      }
    }
    if (options.verbose) {
      fputs("\n\n", stderr);
    }
  }

// That is where I would need to modify NT_FILE if I where to
// create it alongside mappings
  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::AddDataToMapping(const string& data,
				   uintptr_t addr) {
    for (std::map<uint64_t, Mapping>::iterator
	   iter = mappings.begin();
	 iter != mappings.end();
	 ++iter) {
      if (addr >= iter->second.start_address &&
	  addr < iter->second.end_address) {
	Mapping mapping = iter->second;
	if ((addr & ~4095) != iter->second.start_address) {
	  // If there are memory pages in the mapping prior to where the
	  // data starts, truncate the existing mapping so that it ends with
	  // the page immediately preceding the data region.
	  iter->second.end_address = addr & ~4095;
	  if (!mapping.filename.empty()) {
	    // "mapping" is a copy of "iter->second". We are splitting the
	    // existing mapping into two separate ones when we write the data
	    // to the core file. The first one does not have any associated
	    // data in the core file, the second one is backed by data that is
	    // included with the core file.
	    // If this mapping wasn't supposed to be anonymous, then we also
	    // have to update the file offset upon splitting the mapping.
	    mapping.offset += iter->second.end_address -
	      iter->second.start_address;
	  }
	}
	// Create a new mapping that contains the data contents. We often
	// limit the amount of data that is actually written to the core
	// file. But it is OK if the mapping itself extends past the end of
	// the data.
	mapping.start_address = addr & ~4095;
	mapping.data.assign(addr & 4095, 0).append(data);
	mapping.data.append(-mapping.data.size() & 4095, 0);
	mappings[mapping.start_address] = mapping;
	return;
      }
    }
    // Didn't find a suitable existing mapping for the data. Create a new one.
    Mapping mapping;
    mapping.permissions = PF_R | PF_W;
    mapping.start_address = addr & ~4095;
    mapping.end_address =
      (addr + data.size() + 4095) & ~4095;
    mapping.data.assign(addr & 4095, 0).append(data);
    mapping.data.append(-mapping.data.size() & 4095, 0);
    mappings[mapping.start_address] = mapping;
  }

  template<class T, class P, class Prs, class F, class R>
  void
  CrashedProcess<T, P, Prs, F, R>::AugmentMappings(const Options& options,
				  const MinidumpMemoryRange& full_file) {
    // For each thread, find the memory mapping that matches the thread's stack.
    // Then adjust the mapping to include the stack dump.
    for (unsigned i = 0; i < threads.size(); ++i) {
      const T& thread = threads[i];
      AddDataToMapping(string((char *)thread.stack,
			      thread.stack_length),
		       thread.stack_addr);
    }

    // Create a new link map with information about DSOs. We move this map to
    // the beginning of the address space, as this area should always be
    // available.
    static const uintptr_t start_addr = 4096;
    string data;
    struct r_debug deb = { 0 };
    deb.r_version = debug.version;
    deb.r_brk = (ElfW(Addr))debug.brk;
    deb.r_state = r_debug::RT_CONSISTENT;
    deb.r_ldbase = (ElfW(Addr))debug.ldbase;
    deb.r_map = debug.dso_count > 0 ?
      (struct link_map*)(start_addr + sizeof(deb)) : 0;
    data.append((char*)&deb, sizeof(deb));

    struct link_map* prev = 0;
    for (std::vector<MDRawLinkMap>::iterator iter = link_map.begin();
	 iter != link_map.end();
	 ++iter) {
      struct link_map link_m = { 0 };
      link_m.l_addr = (ElfW(Addr))iter->addr;
      link_m.l_name = (char*)(start_addr + data.size() + sizeof(link_m));
      link_m.l_ld = (ElfW(Dyn)*)iter->ld;
      link_m.l_prev = prev;
      prev = (struct link_m*)(start_addr + data.size());
      string filename = full_file.GetAsciiMDString(iter->name);

      // Look up signature for this filename. If available, change filename
      // to point to GUID, instead.
      std::map<uintptr_t, Signature>::const_iterator sig =
	signatures.find((uintptr_t)iter->addr);
      if (sig != signatures.end()) {
	// At this point, we have:
	// old_filename: The path as found via SONAME (e.g. /lib/libpthread.so.0).
	// sig_filename: The path on disk (e.g. /lib/libpthread-2.19.so).
	const char* guid = sig->second.guid;
	string sig_filename = sig->second.filename;
	string old_filename = filename.empty() ? sig_filename : filename;
	string new_filename;

	// First set up the leading path.  We assume dirname always ends with a
	// trailing slash (as needed), so we won't be appending one manually.
	if (options.so_basedir.empty()) {
	  string dirname;
	  if (options.use_filename) {
	    dirname = sig_filename;
	  } else {
	    dirname = old_filename;
	  }
	  size_t slash = dirname.find_last_of('/');
	  if (slash != string::npos) {
	    new_filename = dirname.substr(0, slash + 1);
	  }
	} else {
	  new_filename = options.so_basedir;
	}

	// Insert the module ID if requested.
	if (options.inc_guid &&
	    strcmp(guid, "00000000-0000-0000-0000-000000000000") != 0) {
	  new_filename += guid;
	  new_filename += "-";
	}

	// Decide whether we use the filename or the SONAME (where the SONAME tends
	// to be a symlink to the actual file).
	string basename = options.use_filename ? sig_filename : old_filename;
	size_t slash = basename.find_last_of('/');
	new_filename += basename.substr(slash == string::npos ? 0 : slash + 1);

	if (filename != new_filename) {
	  if (options.verbose) {
	    fprintf(stderr, "0x%" PRIx64": rewriting mapping \"%s\" to \"%s\"\n",
		    static_cast<uint64_t>(link_m.l_addr),
		    filename.c_str(), new_filename.c_str());
	  }
	  filename = new_filename;
	}
      }

      if (std::distance(iter, link_map.end()) == 1) {
	link_m.l_next = 0;
      } else {
	link_m.l_next = (struct link_map*)(start_addr + data.size() +
					     sizeof(link_map) +
					     ((filename.size() + 8) & ~7));
      }
      data.append((char*)&link_m, sizeof(link_m));
      data.append(filename);
      data.append(8 - (filename.size() & 7), 0);
    }
    AddDataToMapping(data, start_addr);

    // Map the page containing the _DYNAMIC array
    if (!dynamic_data.empty()) {
      // Make _DYNAMIC DT_DEBUG entry point to our link map
      for (int i = 0;; ++i) {
	ElfW(Dyn) dyn;
	if ((i+1)*sizeof(dyn) > dynamic_data.length()) {
	no_dt_debug:
	  if (options.verbose) {
	    fprintf(stderr, "No DT_DEBUG entry found\n");
	  }
	  return;
	}
	memcpy(&dyn, dynamic_data.c_str() + i*sizeof(dyn),
	       sizeof(dyn));
	if (dyn.d_tag == DT_DEBUG) {
	  dynamic_data.replace(i*sizeof(dyn) +
			       offsetof(ElfW(Dyn), d_un.d_ptr),
			       sizeof(start_addr),
			       (char*)&start_addr, sizeof(start_addr));
	  break;
	} else if (dyn.d_tag == DT_NULL) {
	  goto no_dt_debug;
	}
      }
      AddDataToMapping(dynamic_data,
		       (uintptr_t)debug.dynamic);
    }
  }

  template<class T, class P, class Prs, class F, class R>
  size_t CrashedProcess<T, P, Prs, F, R>::get_filesz() {
    size_t result =  sizeof(P) +
                     sizeof(Nhdr) + 8 + auxv_length +
                     threads.size() * (
		       (sizeof(Nhdr) + 8 + sizeof(Prs))
		       + sizeof(Nhdr) + 8 + sizeof(F));
    return result;
  }

  template<class T, class P, class Prs, class F, class R>
  bool CrashedProcess<T, P, Prs, F, R>::write_prpsinfo(const Options& options, Nhdr *nhdr) {
  nhdr->n_namesz = 5;
  nhdr->n_descsz = sizeof(P);
  nhdr->n_type = NT_PRPSINFO;
  if (!writea(options.out_fd, nhdr, sizeof(*nhdr)) ||
      !writea(options.out_fd, "CORE\0\0\0\0", 8) ||
      !writea(options.out_fd, &prps, sizeof(P))) {
    return false;
  }
  return true;
  }

  template<class T, class P, class Prs, class F, class R>
  void CrashedProcess<T, P, Prs, F, R>::write_threads(const Options& options) {
    for (unsigned i = 0; i < threads.size(); ++i) {
      if (threads[i].tid != crashing_tid)
	WriteThread(options, threads[i], 0);
      }
  }

  template<class T, class P, class Prs, class F, class R>
  int // ?
  CrashedProcess<T, P, Prs, F, R>::write_core(const Options& options, const MinidumpMemoryRange& dump) {

    const MDRawHeader* header = dump.GetData<MDRawHeader>(0);

  // Always check the system info first, as that allows us to tell whether
  // this is a minidump file that is compatible with our converter.
    bool ok = false;
    for (unsigned i = 0; i < header->stream_count; ++i) {
      const MDRawDirectory* dirent =
        dump.GetArrayElement<MDRawDirectory>(header->stream_directory_rva, i);
      switch (dirent->stream_type) {
      case MD_SYSTEM_INFO_STREAM:
        this->ParseSystemInfo(options, dump.Subrange(dirent->location),
			dump);
        ok = true;
        break;
      default:
        break;
      }
    }
    if (!ok) {
      fprintf(stderr, "Cannot determine input file format.\n");
      exit(1);  // return 1 ?
    }

    for (unsigned i = 0; i < header->stream_count; ++i) {
      const MDRawDirectory* dirent =
        dump.GetArrayElement<MDRawDirectory>(header->stream_directory_rva, i);
      switch (dirent->stream_type) {
      case MD_THREAD_LIST_STREAM:
	this->ParseThreadList(options, dump.Subrange(dirent->location),
                        dump);
        break;
      case MD_LINUX_CPU_INFO:
        ParseCPUInfo(options, dump.Subrange(dirent->location));
        break;
      case MD_LINUX_PROC_STATUS:
        ParseProcessStatus(options,
			   dump.Subrange(dirent->location));
        break;
      case MD_LINUX_LSB_RELEASE:
        ParseLSBRelease(options, dump.Subrange(dirent->location));
        break;
      case MD_LINUX_ENVIRON:
        ParseEnvironment(options, dump.Subrange(dirent->location));
        break;
      case MD_LINUX_MAPS:
        ParseMaps(options, dump.Subrange(dirent->location));
        break;
      case MD_LINUX_AUXV:
        ParseAuxVector(options, dump.Subrange(dirent->location));
        break;
      case MD_LINUX_CMD_LINE:
        ParseCmdLine(options, dump.Subrange(dirent->location));
        break;
      case MD_LINUX_DSO_DEBUG:
        ParseDSODebugInfo(options, dump.Subrange(dirent->location),
			  dump);
        break;
      case MD_EXCEPTION_STREAM:
        ParseExceptionStream(options,
			     dump.Subrange(dirent->location));
        break;
      case MD_MODULE_LIST_STREAM:
        ParseModuleStream(options, dump.Subrange(dirent->location),
				    dump);
        break;
      default:
        if (options.verbose)
          fprintf(stderr, "Skipping %x\n", dirent->stream_type);
      }
    }

    AugmentMappings(options, dump);

    // Write the ELF header. The file will look like:
    //   ELF header
    //   Phdr for the PT_NOTE
    //   Phdr for each of the thread stacks
    //   PT_NOTE
    //   each of the thread stacks
    Ehdr ehdr;
    memset(&ehdr, 0, sizeof(Ehdr));
    ehdr.e_ident[0] = ELFMAG0;
    ehdr.e_ident[1] = ELFMAG1;
    ehdr.e_ident[2] = ELFMAG2;
    ehdr.e_ident[3] = ELFMAG3;
    ehdr.e_ident[4] = ELF_CLASS;
    ehdr.e_ident[5] = sex() ? ELFDATA2MSB : ELFDATA2LSB;
    ehdr.e_ident[6] = EV_CURRENT;
    ehdr.e_type     = ET_CORE;
    ehdr.e_machine  = elf_arch;
    ehdr.e_version  = EV_CURRENT;
    ehdr.e_phoff    = sizeof(Ehdr);
    ehdr.e_ehsize   = sizeof(Ehdr);
    ehdr.e_phentsize= sizeof(Phdr);
    ehdr.e_phnum    = 1 +                         // PT_NOTE
                      mappings.size();  // memory mappings
    ehdr.e_shentsize= sizeof(Shdr);
    if (!writea(options.out_fd, &ehdr, sizeof(Ehdr)))
      return 1;

  // https://github.com/torvalds/linux/blob/b9151761021e25c024a6670df4e7c43ffbab0e1d/fs/binfmt_elf.c#L1580
  /*
   * Format of NT_FILE note:
   *
   * long count     -- how many files are mapped
   * long page_size -- units for file_ofs
   * array of [COUNT] elements of
   *   long start
   *   long end
   *   long file_ofs
   * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
   */

  //Need a vector of long
  //And a string buffer. Need string concatenation
    std::vector<long> filemaps;
    std::string filenames;
    long count = 0;

    for (std::map<uint64_t, Mapping>::const_iterator iter =
	   mappings.begin();
	 iter != mappings.end(); ++iter) {
      const Mapping& mapping = iter->second;
      // printf("-%s-\n", mapping.filename.c_str());
      if (mapping.permissions == 0xFFFFFFFF || mapping.filename.empty())
	continue;
      filemaps.push_back((long) mapping.start_address);
      // printf("mapping start 0x%x\n", (unsigned int) mapping.start_address);
      filemaps.push_back((long) mapping.end_address);
      filemaps.push_back((long) mapping.offset);
      filenames += mapping.filename;
      filenames.append(1, '\0');
      ++count;
    }

    // the way NT_FILES work means the descsz is obtained by summation of different
    // elements and not just the size of 1 element. The issue there is alignment.
    // so let's try to do it by hand with align_power from binutils
    size_t file_descsz = (2 + filemaps.size()) * sizeof(long) + filenames.size();
    size_t file_aligned = align_power(file_descsz, 2);

    size_t offset = sizeof(Ehdr) + ehdr.e_phnum * sizeof(Phdr);
    //this does not work b/c prpsinfo prstatus fpe... => member function
    size_t filesz = sizeof(Nhdr) + 8 +
                    // sizeof(Nhdr) + 8 + sizeof(user) +
                    // siginfo
                    sizeof(Nhdr) + 8 + sizeof(siginfo_t) +
                    // NT_FILES:
                    sizeof(Nhdr) + 8 + file_aligned +
                    get_filesz();

    printf("filesz is %lu\n", filesz);


    Phdr phdr;
    memset(&phdr, 0, sizeof(Phdr));
    phdr.p_type = PT_NOTE;
    phdr.p_offset = offset;
    phdr.p_filesz = filesz;
    if (!writea(options.out_fd, &phdr, sizeof(phdr)))
      return 1;

    phdr.p_type = PT_LOAD;
    phdr.p_align = 4096;
    size_t note_align = phdr.p_align - ((offset+filesz) % phdr.p_align);
    if (note_align == phdr.p_align)
      note_align = 0;
    offset += note_align;

    for (std::map<uint64_t, Mapping>::const_iterator iter =
	   mappings.begin();
	 iter != mappings.end(); ++iter) {
      const Mapping& mapping = iter->second;
      if (mapping.permissions == 0xFFFFFFFF) {
	// This is a map that we found in MD_MODULE_LIST_STREAM (as opposed to
	// MD_LINUX_MAPS). It lacks some of the information that we would like
	// to include.
	phdr.p_flags = PF_R;
      } else {
	phdr.p_flags = mapping.permissions;
      }
      phdr.p_vaddr = mapping.start_address;
      phdr.p_memsz = mapping.end_address - mapping.start_address;
      if (mapping.data.size()) {
	offset += filesz;
	filesz = mapping.data.size();
	phdr.p_filesz = mapping.data.size();
	phdr.p_offset = offset;
      } else {
	phdr.p_filesz = 0;
	phdr.p_offset = 0;
      }
      if (!writea(options.out_fd, &phdr, sizeof(phdr)))
	return 1;
    }

    Nhdr nhdr;
    memset(&nhdr, 0, sizeof(nhdr));

    if (!write_prpsinfo(options, &nhdr))
      return  1;

    nhdr.n_descsz = auxv_length;
    nhdr.n_type = NT_AUXV;
    if (!writea(options.out_fd, &nhdr, sizeof(nhdr)) ||
	!writea(options.out_fd, "CORE\0\0\0\0", 8) ||
	!writea(options.out_fd, auxv, auxv_length)) {
      return 1;
    }

    for (unsigned i = 0; i < threads.size(); ++i) {
      if (threads[i].tid == crashing_tid) {
	WriteThread(options, threads[i], fatal_signal);
	// NT_SIGINFO needs to get crashing thread tid
	nhdr.n_descsz = sizeof(siginfo_t);
	nhdr.n_type = NT_SIGINFO;
	if (!writea(options.out_fd, &nhdr, sizeof(nhdr)) ||
	    !writea(options.out_fd, "CORE\0\0\0\0", 8) ||
	    !writea(options.out_fd, &siginfo, sizeof(siginfo_t))) {
	  return 1;
	}
	break;
      }
    }

    // NT_FILE
    long page_size = 4096;
    nhdr.n_descsz = file_descsz;
    nhdr.n_type = NT_FILE;

    if (!writea(options.out_fd, &nhdr, sizeof(nhdr)) ||
	!writea(options.out_fd, "CORE\0\0\0\0", 8) ||
	!writea(options.out_fd, &count, sizeof(long)) ||
	!writea(options.out_fd, &page_size, sizeof(long)) ||
	!writea(options.out_fd, &(filemaps[0]), filemaps.size() * sizeof(long)) ||
	!writea(options.out_fd, filenames.data(), filenames.size())) {
      printf("Failed nt_file\n");
      return 1;
    }
    // and do not forget I need to write the alignment to file, but it should not be in descsz.
    size_t fill_aligned = file_aligned - file_descsz;
    if (fill_aligned) {
      google_breakpad::scoped_array<char> scratch(new char[fill_aligned]);
      memset(scratch.get(), 0, note_align);
      if (!writea(options.out_fd, scratch.get(), fill_aligned))
	return 1;
    }

    write_threads(options);

    printf("note_align %lu\n", note_align);
    if (note_align) {
      google_breakpad::scoped_array<char> scratch(new char[note_align]);
      memset(scratch.get(), 0, note_align);
      if (!writea(options.out_fd, scratch.get(), note_align))
	return 1;
    }

    for (std::map<uint64_t, Mapping>::const_iterator iter =
	   mappings.begin();
	 iter != mappings.end(); ++iter) {
      const Mapping& mapping = iter->second;
      if (mapping.data.size()) {
	if (!writea(options.out_fd, mapping.data.c_str(), mapping.data.size()))
	  return 1;
      }
    }

    if (options.out_fd != STDOUT_FILENO) {
      close(options.out_fd);
    }

    return 0;
  }


}
