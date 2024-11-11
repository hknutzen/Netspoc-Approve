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
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/ios"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/linux"
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
	var result RealDevice
	info, _ := codefiles.LoadInfoFile(fname)
	switch info.Model {
	case "ASA":
		result = asa.Setup()
	case "IOS":
		result = ios.Setup()
	case "Linux":
		result = &linux.State{}
	case "NSX":
		result = &nsx.State{}
	case "PAN-OS":
		result = &panos.State{}
	default:
		errlog.Abort("Unexpected model %q in file %s.info\n",
			info.Model, fname)
	}
	return result
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
	return errlog.HandleAbort(func() int {
		errlog.Quiet = quiet
		errlog.SetStderrLog(logFile)
		s := &state{RealDevice: getRealDevice(fname)}
		s.config = cfg
		if logDir != "" {
			s.logFname = path.Join(logDir, path.Base(fname))
		}
		var err error
		if isCompare {
			err = s.compare(fname)
		} else {
			err = s.approve(fname)
		}
		s.CloseConnection()
		if err != nil {
			errlog.Abort("%v", err)
		}
		return 0
	})
}

func CompareFiles(fname1, fname2 string, quiet bool) int {
	return errlog.HandleAbort(func() int {
		errlog.Quiet = quiet
		errlog.SetStderrLog("")
		s := &state{RealDevice: getRealDevice(fname2)}
		conf1, err := s.loadSpoc(fname1)
		if err != nil {
			errlog.Abort("%v", err)
		}
		if err := s.getCompare(conf1, fname2); err != nil {
			errlog.Abort("%v", err)
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
		errlog.Warning("%v", w)
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
		errlog.DoLog(logFH, "No changes applied")
		return nil
	}
	return s.ApplyCommands(logFH)
}

func (s *state) showCompareInfo() {
	if !s.HasChanges() {
		errlog.Info("comp: device unchanged")
	} else {
		errlog.Info("comp: *** device changed ***")
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
		return nil, fmt.Errorf("While reading file %s: %v", b, err)
	}
	return c, nil
}

// Set lock for exclusive approval.
func SetLock(fname string, cfg *program.Config) (*os.File, error) {
	lockDir := path.Join(cfg.BaseDir, "lock")
	os.Mkdir(lockDir, 0755)
	lockFile := path.Join(lockDir, path.Base(fname))
	fh, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	err = syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		err = fmt.Errorf("Approve in progress for %s", fname)
	}
	return fh, err
}

func (s *state) getLogFH(ext string) (*os.File, error) {
	if s.logFname == "" {
		return nil, nil
	}
	fname := s.logFname + ext
	errlog.MoveLogFile(fname)
	return errlog.CreateWithPath(fname)
}

func closeLogFH(fh *os.File) {
	if fh != nil {
		fh.Close()
	}
}
