{ pkgs }: {
	deps = [
		pkgs.clang_12
		pkgs.gdb
		pkgs.vim
		pkgs.ccls
		pkgs.valgrind
		pkgs.zlib
		pkgs.python3
		pkgs.hexedit
		pkgs.pcap
	];
}
