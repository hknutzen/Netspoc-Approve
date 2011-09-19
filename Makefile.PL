use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	      'NAME'          => 'Netspoc::Approve',
	      'VERSION'       => '1.040',
	      'EXE_FILES'     => [ qw(bin/drc3.pl bin/rex3 bin/approve.pl bin/compare-all bin/missing-approve bin/start-jobs) ],
	      'INSTALLSCRIPT' => '/usr/local/bin',
	      'PREREQ_PM'     => {
		  'Expect' => 0,
		  'Algorithm::Diff' => 0,
	      },
);
