#!/usr/bin/python
# Flag use_nfm to decide if NFM libs are used to compile program
use_nfm = ARGUMENTS.get('use_nfm', 'false')
# Flag to decide if gdb enabled
gdb_enable = ARGUMENTS.get('debug', 'false')

# C flags
cflags = ['-w']
# Library paths
lib_path = ['.']
# Library names
libs = ['pcap', 'pthread']
# Header file path
cpp_path=['.']
rpath = []

if use_nfm.lower() == 'true':
	# NFM library names
	libs += ['nfm', 'nfm_framework', 'nfm_error', 'nfm_packet', 'nfm_log' \
		,'nfm_rules', 'nfm_platform', 'nfe', 'nfp', 'ns_armctrl']
	# NFM library path
	lib_path.append('/opt/netronome/lib')
	# NFM header file path
	cpp_path.append('/opt/netronome/nfm/include')
	# NFM rpath
	rpath.append('/opt/netronome/lib')
else:
	print '(default) use_nfm=false'
	
if gdb_enable.lower() == 'true':
	cflags.append('-g')
else:
	print '(default) debug=false'
	
env = Environment(CCFLAGS=' '.join(cflags))
# Compile the programs
env.Program(target = 'httpdump',
		source = Glob('*.c'),
		LIBPATH = lib_path,
		LIBS = libs,
		CPPPATH = cpp_path,
		RPATH = rpath)
