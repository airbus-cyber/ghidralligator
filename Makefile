
FLAGS=-Wall -Wno-sign-compare
PRJ_NAME=ghidralligator
STD_LIB_VERSION=c++17
GHIDRA_SRC=-I./src
EMU_HEADERS=-I./headers
LNK=src/libsla.a


libsla.a:
	$(MAKE) -C src/ $@


libsla_dbg.a:
	$(MAKE) -C src/ $@


ghidralligator_dbg: libsla_dbg.a
	rm -f $(PRJ_NAME)_dbg
	g++ -g $(FLAGS) -lmcheck -std=$(STD_LIB_VERSION) $(PRJ_NAME).cc ./user_hooks/*_hooks.cc fuzzers.cc memory.cc cmdline.cc parser.cc afl.cc utils.cc $(GHIDRA_SRC) $(EMU_HEADERS) -o $(PRJ_NAME)_dbg -ldl src/libsla_dbg.a -lstdc++fs


ghidralligator: libsla.a
	rm -f $(PRJ_NAME)
	g++ -O3 $(FLAGS) -std=$(STD_LIB_VERSION) $(PRJ_NAME).cc ./user_hooks/*_hooks.cc fuzzers.cc memory.cc cmdline.cc parser.cc afl.cc utils.cc $(GHIDRA_SRC) $(EMU_HEADERS) -o $(PRJ_NAME) -ldl $(LNK) -lstdc++fs

ghidralligator_fast: libsla.a
	rm -f $(PRJ_NAME)_fast*
	cat ghidralligator.cc | grep -v printf | grep -v debug_print | grep -v verbose_print | grep -v hexdump  > $(PRJ_NAME)_fast.cc
	g++ -O3 $(FLAGS) -std=$(STD_LIB_VERSION) $(PRJ_NAME)_fast.cc ./user_hooks/*_hooks.cc fuzzers.cc memory.cc cmdline.cc parser.cc afl.cc utils.cc $(GHIDRA_SRC) $(EMU_HEADERS) -o $(PRJ_NAME)_fast -ldl $(LNK) -lstdc++fs


clean:
	rm -f $(LNK)
	$(MAKE) -C src/ clean
	rm -rf *.o $(PRJ_NAME) $(PRJ_NAME)_dbg
	rm -rf ./tmp_dir/

