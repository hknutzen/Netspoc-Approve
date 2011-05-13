use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	      'NAME'          => 'Netspoc::Approve',
	      'VERSION'       => '1.034',
	      'EXE_FILES'     => [ qw(bin/drc3.pl bin/rex3) ],
	      'INSTALLSCRIPT' => '/usr/local/bin',
	      'PREREQ_PM'     => {
		  'Expect' => 0,
		  'Algorithm::Diff' => 0,
	      },
);
