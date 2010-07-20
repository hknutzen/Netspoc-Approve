use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'          => 'Netspoc::Approve',
    'VERSION'       => '1.021',
    'EXE_FILES'	    => [ qw(bin/drc3.pl bin/rex3) ],
    'INSTALLSCRIPT' => '/usr/local/bin',
);
