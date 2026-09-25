package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// osVersion holds a resolved Windows version.
type osVersion struct {
	major uint32
	minor uint32
	build uint32
}

func (v osVersion) String() string {
	return fmt.Sprintf("%d.%d build %d", v.major, v.minor, v.build)
}

// getWindowsVersion returns the real OS version via RtlGetVersion, which is not
// subject to application-manifest version shimming (unlike GetVersionEx).
func getWindowsVersion() (osVersion, error) {
	type osVersionInfoEx struct {
		osVersionInfoSize uint32
		majorVersion      uint32
		minorVersion      uint32
		buildNumber       uint32
		platformID        uint32
		csdVersion        [128]uint16
		servicePackMajor  uint16
		servicePackMinor  uint16
		suiteMask         uint16
		productType       byte
		reserved          byte
	}

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")

	var info osVersionInfoEx
	info.osVersionInfoSize = uint32(unsafe.Sizeof(info))

	ret, _, _ := rtlGetVersion.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		return osVersion{}, fmt.Errorf("RtlGetVersion failed (status=0x%x)", ret)
	}

	return osVersion{
		major: info.majorVersion,
		minor: info.minorVersion,
		build: info.buildNumber,
	}, nil
}

// checkSystem verifies the host meets the agent”s requirements:
// Windows 10 or newer, 64-bit. Windows 10 and 11 both report major version 10;
// Windows 11 is build >= 22000. Anything below major 10 (Win 8.1/7) is rejected.
func checkSystem() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("unsupported architecture %q; x64 required", runtime.GOARCH)
	}

	v, err := getWindowsVersion()
	if err != nil {
		return fmt.Errorf("cannot determine Windows version: %w", err)
	}

	if v.major < 10 {
		return fmt.Errorf("Windows 10 or newer required, found version %s", v)
	}

	return nil
}

// windowsProductName returns a friendly OS label for logging.
func windowsProductName(v osVersion) string {
	switch {
	case v.major == 10 && v.build >= 22000:
		return "Windows 11"
	case v.major == 10:
		return "Windows 10"
	default:
		return "Windows " + v.String()
	}
}
