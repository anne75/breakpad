# Goal

Breakpad has a linux tool `minidump-2-core` that transforms a minidump into a core dump suitable for gdb.  
This code is architecture dependent, meaning the binary will work only on one architecture, and target only that same architecture. That can be a bit of an issue when you run a program on x86_64 but would like to make core dumps out of minidumps created on both x86_64 and aarch64 architectures.  
So my goal here was to try to adapt the code to pick the architecture at runtime and to run as such:  
`minidump-2-core -aarch64 /path/to/minidump` or `minidump-2-core -x86_64 ...`
My other goal is to learn c++. This work is to be regarded as an exercise (still important to me).  

# Basic idea

The [original code](src/tools/linux/md2core/minidump-2-core.cc.original) (updated_original was written after and the change is irrelevant to my problem) is based on one struct holding different parts of an elf file, gathering the values from the minidump and writing them in order to create a core dump.  
All core files on all architecture have those different parts. However the underlying strctures of these parts can differ. For example, if mappings remain the same, threads are widely differents. Others only differ by the type of one of their members.  
  
I thought I could have a [base class](src/tools/linux/md2core/md2core.h), where I would keep everything that stays the same, and create derived classes, one for each architecture ([x86_64](src/tools/linux/md2core/md2core_x86_64.h)  and [aarch64](src/tools/linux/md2core/md2core_aarch64.h).  
The base class should not be instantiated, and declare the member functions that use threads for example as virtual. The derived class would contain the proper implementation.
So from what I understand the base class is abstract.  

Then, since threads and a few other class members have a type that depends on the architecture, I need to use templates.  
So my base class is templated, and the derived class replace those with the right type.  

# Issues

### Git
Maybe next time I should try to fork breakpad from github and then `git submodule foreach 'git config -f $toplevel/.git/config submodule.$name.ignore all'`  
. As forking only would not work, but I did not remember that until following the README guidelines.  But that is not where I want to focus right now.  

### Writing the code
So starting with that kind of thing to learn c++ was maybe not the easiest path, but I might as well try to finish it. I hade never done templating, and only limited OOP in python. Coming from C I also had no knowledge of c++. So I started with just a very generic idea, and then I tried to figure out a way to implement it.  
I have no idea if it is the most obvious/usual way to solve that kind of problems.  

### Compiling
I have never done any complex project before. I am absolutely not familiar with configure or make. So what I did is run `./configure` and `make`, then searched for `md2core` and `minidump-2-core` occurences. Here are the 2 lines where they appear:  
```
depbase=`echo src/tools/linux/md2core/minidump-2-core.o | sed 's|[^/]*$|.deps/&|;s|\.o$||'`;\
g++ -DHAVE_CONFIG_H -I. -I./src  -I./src   -Wmissing-braces -Wnon-virtual-dtor -Woverloaded-virtual -Wreorder -Wsign-compare -Wunused-local-typedefs -Wunused-variable -Wvla -Werror -fPIC -g -O2 -std=c++11 -MT src/tools/linux/md2core/minidump-2-core.o -MD -MP -MF $depbase.Tpo -c -o src/tools/linux/md2core/minidump-2-core.o src/tools/linux/md2core/minidump-2-core.cc &&\
mv -f $depbase.Tpo $depbase.Po  
g++  -Wmissing-braces -Wnon-virtual-dtor -Woverloaded-virtual -Wreorder -Wsign-compare -Wunused-local-typedefs -Wunused-variable -Wvla -Werror -fPIC -g -O2 -std=c++11   -o src/tools/linux/md2core/minidump-2-core src/common/linux/memory_mapped_file.o src/common/path_helper.o src/tools/linux/md2core/minidump-2-core.o 
```
Then I reused those commands to compile only my files. I updated the first command to compile all `*.cc` files in the `/md2core/` directory.
Good news is I can make object files. Bad news is linking starts really bad. This is just the beginning:  
```
/usr/lib/gcc/x86_64-linux-gnu/5/../../../x86_64-linux-gnu/crt1.o: In function `_start':  
(.text+0x20): undefined reference to `main'
md2core_aarch64.o: In function `md2core::CrashedProcessAarch64::CrashedProcessAarch64()':  
/home/anne/workspace/Cpp/breakpad/src/src/tools/linux/md2core/md2core_aarch64.cc:6: undefined reference to `vtable for md2core::CrashedProcessAarch64'  
md2core_aarch64.o: In function `md2core::CrashedProcessAarch64::ParseSystemInfo(md2core::Options const&, google_breakpad::MinidumpMemoryRange const&, google_breakpad::MinidumpMemoryRange const&)':  
/home/anne/workspace/Cpp/breakpad/src/src/tools/linux/md2core/md2core_aarch64.cc:57: undefined reference to `md2core::CrashedProcess<md2core::Threadaarch64, md2core::prpsinfoaarch64, md2core::prstatusaarch64, md2core::user_fpsimd_struct, md2core::user_regsaarch64_struct>::ParseSystemInfo(md2core::Options const&, google_breakpad::MinidumpMemoryRange const&, google_breakpad::MinidumpMemoryRange const&)'  
```
Here I am at a loss to finding a good google search, and I am not even sure I would understand the answers.
