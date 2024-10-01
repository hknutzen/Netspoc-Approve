############################################################
=TITLE=Missing config file
=INPUT=NONE
=SETUP=
rm .netspoc-approve
=ERROR=
Error: No config file found in [.netspoc-approve /usr/local/etc/netspoc-approve /etc/netspoc-approve]
=END=

############################################################
=TITLE=Missing current policy
=INPUT=NONE
=SETUP=
rm current
=ERROR=
Error: Can't get 'current' policy directory: lstat current: no such file or directory
=END=

############################################################
=TITLE=Missing code directory
=INPUT=
--p2/code/A
some code
=SETUP=
rm -rf p2/code
=ERROR=
Error: lstat p2/code: no such file or directory
=END=
