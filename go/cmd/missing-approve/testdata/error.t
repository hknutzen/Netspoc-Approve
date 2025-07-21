############################################################
=TITLE=Missing config file
=SETUP=
rm .netspoc-approve
=ERROR=
Error: No config file found in [.netspoc-approve /usr/local/etc/netspoc-approve /etc/netspoc-approve]
=END=

############################################################
=TITLE=Missing current policy
=SETUP=
rm policies/current
=ERROR=
Error: Can't get 'current' policy directory: lstat policies/current: no such file or directory
=END=

############################################################
=TITLE=Missing code directory
=INPUT=
--policies/p2/code/A
some code
=SETUP=
rm -rf policies/p2/code
=ERROR=
Error: lstat policies/p2/code: no such file or directory
=END=
