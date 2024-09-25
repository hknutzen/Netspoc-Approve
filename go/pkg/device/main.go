package device

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"syscall"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	myerror "github.com/hknutzen/Netspoc-Approve/go/pkg/myerror"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
	"github.com/spf13/pflag"
)

type RealDevice interface {
	LoadDevice(fname string, c *program.Config, l1, l2 *os.File) (
		DeviceConfig, error)
	ParseConfig(data []byte, fName string) (DeviceConfig, error)
	GetChanges(c1, c2 DeviceConfig) error
	GetErrUnmanaged() []error
	ApplyCommands(*os.File) error
	HasChanges() bool
	ShowChanges() string
	CloseConnection()
}

type DeviceConfig interface {
	MergeSpoc(DeviceConfig) DeviceConfig
}

type state struct {
	RealDevice
	config   *program.Config
	logFname string
}

func Main(dev RealDevice, fs *pflag.FlagSet) int {
	s := &state{RealDevice: dev}
	getString := func(fs *pflag.FlagSet, name string) string {
		val, _ := fs.GetString(name)
		return val
	}
	myerror.Quiet, _ = fs.GetBool("quiet")
	return myerror.HandleAbort(func() int {
		var err error
		args := fs.Args()
		switch len(args) {
		case 2:
			q := fs.Changed("quiet")
			n := fs.NFlag()
			if q && n > 1 || !q && n > 0 {
				fs.Usage()
				return 1
			}
			myerror.SetStderrLog("")
			err = s.compareFiles(args[0], args[1])
		case 1:
			fname := args[0]
			s.config, err = program.LoadConfig()
			if err != nil {
				break
			}
			s.setLock(fname)
			s.config.User = getString(fs, "user")
			s.setLogDir(getString(fs, "logdir"), fname)
			myerror.SetStderrLog(getString(fs, "LOGFILE"))
			if v, _ := fs.GetBool("compare"); v {
				err = s.compare(fname)
			} else {
				err = s.approve(fname)
			}
			s.CloseConnection()
		}
		if err != nil {
			myerror.Abort("%v", err)
		}
		return 0
	})
}

func (s *state) compareFiles(fname1, fname2 string) error {
	conf1, err := s.loadSpoc(fname1)
	if err != nil {
		return err
	}
	err = s.getCompare(conf1, fname2)
	if err != nil {
		return err
	}
	s.showCompareInfo()
	fmt.Print(s.ShowChanges())
	return nil
}

func (s *state) compare(fname string) error {
	err := s.compareDevice(fname)
	if err != nil {
		return err
	}
	for _, w := range s.GetErrUnmanaged() {
		myerror.Warning("%v", w)
	}
	s.showCompareInfo()
	if s.logFname != "" && s.HasChanges() {
		logFH, err := s.getLogFH(".cmp")
		if err != nil {
			return err
		}
		defer closeLogFH(logFH)
		fmt.Fprint(logFH, s.ShowChanges())
	}
	return nil
}

func (s *state) approve(fname string) error {
	err := s.compareDevice(fname)
	if err != nil {
		return err
	}
	if l := s.GetErrUnmanaged(); l != nil {
		return l[0]
	}
	return s.applyCommands()
}

func (s *state) compareDevice(fname string) error {
	conf1, err := s.loadDevice(fname)
	if err != nil {
		return err
	}
	return s.getCompare(conf1, fname)
}

func (s *state) loadDevice(fname string) (DeviceConfig, error) {
	logConfig, err := s.getLogFH(".config")
	if err != nil {
		return nil, err
	}
	defer closeLogFH(logConfig)
	logLogin, err := s.getLogFH(".login")
	if err != nil {
		return nil, err
	}
	defer closeLogFH(logLogin)
	return s.LoadDevice(fname, s.config, logLogin, logConfig)
}

func (s *state) applyCommands() error {
	logFH, err := s.getLogFH(".change")
	if err != nil {
		return err
	}
	defer closeLogFH(logFH)
	if !s.HasChanges() {
		myerror.DoLog(logFH, "No changes applied")
		return nil
	}
	return s.ApplyCommands(logFH)
}

func (s *state) showCompareInfo() {
	if !s.HasChanges() {
		myerror.Info("comp: device unchanged")
	} else {
		myerror.Info("comp: *** device changed ***")
	}
}

func (s *state) getCompare(c1 DeviceConfig, fname string) error {
	c2, err := s.loadSpoc(fname)
	if err != nil {
		return err
	}
	return s.GetChanges(c1, c2)
}

func (s *state) loadSpoc(v4Path string) (DeviceConfig, error) {
	v6Path := codefiles.GetIPv6Fname(v4Path)
	conf4, err := s.loadSpocFile(v4Path)
	if err != nil {
		return nil, err
	}
	conf6, err := s.loadSpocFile(v6Path)
	if err != nil {
		return nil, err
	}
	conf := conf4.MergeSpoc(conf6)
	return s.addRaw(conf, v4Path)
}

func (s *state) addRaw(conf DeviceConfig, v4Path string) (DeviceConfig, error) {
	rawPath := v4Path + ".raw"
	raw, err := s.loadSpocFile(rawPath)
	if err != nil {
		return nil, err
	}
	conf = conf.MergeSpoc(raw)
	return conf, nil
}

func (s *state) loadSpocFile(fname string) (DeviceConfig, error) {
	data, err := os.ReadFile(fname)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("Can't %v", err)
	}
	c, err := s.ParseConfig(data, fname)
	if err != nil {
		b := path.Base(fname)
		return nil, fmt.Errorf("While reading %s: %v", b, err)
	}
	return c, nil
}

// Set lock for exclusive approval.
// Store file handle in global var, so it isn't closed immediately.
// File is closed automatically after program exit.
var lockFH *os.File

func (s *state) setLock(fname string) {
	lockFile := path.Join(s.config.LockfileDir, path.Base(fname))
	_, statErr := os.Stat(lockFile)
	fh, err := os.Create(lockFile)
	if err != nil {
		myerror.Abort("Can't %v", err)
	}
	// Make newly created lock file writable for other users.
	if statErr != nil && errors.Is(statErr, fs.ErrNotExist) {
		os.Chmod(lockFile, 0666)
	}
	err = syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		myerror.Abort("Approve in progress for %s", fname)
	}
	lockFH = fh
}

func (s *state) setLogDir(logDir, file string) {
	if logDir != "" {
		s.logFname = path.Join(logDir, path.Base(file))
	}
}

func (s *state) getLogFH(ext string) (*os.File, error) {
	if s.logFname == "" {
		return nil, nil
	}
	fname := s.logFname + ext
	myerror.MoveLogFile(fname)
	return myerror.CreateWithPath(fname)
}

func closeLogFH(fh *os.File) {
	if fh != nil {
		fh.Close()
	}
}
