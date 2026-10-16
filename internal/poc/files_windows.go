package poc

import (
	"bytes"
	"os"

	"golang.org/x/sys/windows"
)

const readFlags = 0

func singleLink(file *os.File, _ os.FileInfo) bool {
	var info windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) == nil && info.NumberOfLinks == 1
}

// Windows reports no execute bits, so a shebang stands in for one.
func executable(_ os.FileInfo, data []byte) bool {
	return bytes.HasPrefix(data, []byte("#!"))
}
