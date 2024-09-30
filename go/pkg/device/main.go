package device

import (
	"errors"
	"fmt"
	"os"
	"path"
	"syscall"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/asa"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/deviceconf"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/ios"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/linux"
	myerror "github.com/hknutzen/Netspoc-Approve/go/pkg/myerror"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/nsx"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/panos"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type RealDevice interface {
	LoadDevice(fname string, c *program.Config, l1, l2 *os.File) (
		deviceconf.Config, error)
	ParseConfig(data []byte, fName string) (deviceconf.Config, error)
	GetChanges(c1, c2 deviceconf.Config) error
	GetErrUnmanaged() []error
	ApplyCommands(*os.File) error
	HasChanges() bool
	ShowChanges() string
	CloseConnection()
}

func getRealDevice(fname string) RealDevice {
	info, _ := codefiles.LoadInfoFile(fname)
	switch info.Model {
	case "ASA":
		return asa.Setup()
	case "IOS":
		return ios.Setup()
	case "Linux":
		return &linux.State{}
	case "NSX":
		return &nsx.State{}
	case "PAN-OS":
		return &panos.State{}
	default:
		myerror.Abort("Unexpected model %q in file %s.info\n",
			info.Model, fname)
	}
	return nil
}

type state struct {
	RealDevice
	config   *program.Config
	logFname string
}

func ApproveOrCompare(
	isCompare bool,
	fname string,
	cfg *program.Config,
	logDir string,
	logFile string,
	quiet bool,
) int {
	return myerror.HandleAbort(func() int {
		myerror.Quiet = quiet
		myerror.SetStderrLog(logFile)
		s := &state{RealDevice: getRealDevice(fname)}
		s.config = cfg
		if logDir != "" {
			s.setLogDir(logDir, fname)
		}
		var err error
		if isCompare {
			err = s.compare(fname)
		} else {
			err = s.approve(fname)
		}
		s.CloseConnection()
		if err != nil {
			myerror.Abort("%v", err)
		}
		return 0
	})
}

func CompareFiles(fname1, fname2 string, quiet bool) int {
	return myerror.HandleAbort(func() int {
		myerror.Quiet = quiet
		myerror.SetStderrLog("")
		s := &state{RealDevice: getRealDevice(fname2)}
		conf1, err := s.loadSpoc(fname1)
		if err != nil {
			myerror.Abort("%v", err)
		}
		if err := s.getCompare(conf1, fname2); err != nil {
			myerror.Abort("%v", err)
		}
		s.showCompareInfo()
		fmt.Print(s.ShowChanges())
		return 0
	})
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

func (s *state) loadDevice(fname string) (deviceconf.Config, error) {
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

func (s *state) getCompare(c1 deviceconf.Config, fname string) error {
	c2, err := s.loadSpoc(fname)
	if err != nil {
		return err
	}
	return s.GetChanges(c1, c2)
}

func (s *state) loadSpoc(v4Path string) (deviceconf.Config, error) {
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

func (s *state) addRaw(conf deviceconf.Config, v4Path string) (deviceconf.Config, error) {
	rawPath := v4Path + ".raw"
	raw, err := s.loadSpocFile(rawPath)
	if err != nil {
		return nil, err
	}
	conf = conf.MergeSpoc(raw)
	return conf, nil
}

func (s *state) loadSpocFile(fname string) (deviceconf.Config, error) {
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
func SetLock(fname, dir string) (*os.File, error) {
	lockFile := path.Join(dir, path.Base(fname))
	fh, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	err = syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		err = fmt.Errorf("Approve in progress for %s", fname)
	}
	return fh, err
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
