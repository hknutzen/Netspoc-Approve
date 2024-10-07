package device

import (
	"errors"
	"fmt"
	"os"
	"path"
	"syscall"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/asa"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/checkpoint"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/cisco"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/ios"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/linux"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/nsx"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/panos"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type RealDevice interface {
	LoadDevice(fname string, c *program.Config, l1, l2 *os.File) error
	LoadNetspoc(data []byte, fName string) error
	MoveNetspoc2DeviceConfig()
	GetChanges() error
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
		result = cisco.Setup(&asa.State{})
	case "IOS":
		result = cisco.Setup(&ios.State{})
	case "CHECKPOINT":
		result = &checkpoint.State{}
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
		if err := s.loadSpoc(fname1); err != nil {
			errlog.Abort("%v", err)
		}
		s.MoveNetspoc2DeviceConfig()
		if err := s.loadSpoc(fname2); err != nil {
			errlog.Abort("%v", err)
		}
		if err := s.GetChanges(); err != nil {
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
	if err := s.loadSpoc(fname); err != nil {
		return err
	}
	if err := s.loadDevice(fname); err != nil {
		return err
	}
	return s.GetChanges()
}

func (s *state) loadDevice(fname string) error {
	logConfig, err := s.getLogFH(".config")
	if err != nil {
		return err
	}
	defer closeLogFH(logConfig)
	logLogin, err := s.getLogFH(".login")
	if err != nil {
		return err
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

func (s *state) loadSpoc(v4Path string) error {
	if err := s.loadSpocFile(v4Path); err != nil {
		return err
	}
	v6Path := codefiles.GetIPv6Fname(v4Path)
	if err := s.loadSpocFile(v6Path); err != nil {
		return err
	}
	return s.loadSpocFile(v4Path + ".raw")
}

func (s *state) loadSpocFile(fname string) error {
	data, err := os.ReadFile(fname)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Can't %v", err)
	}
	if err := s.LoadNetspoc(data, fname); err != nil {
		return fmt.Errorf("While reading file %s: %v", path.Base(fname), err)
	}
	return nil
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
