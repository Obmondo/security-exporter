package action

import (
	"os"
	"os/exec"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"go.uber.org/zap"
)

type AptAction interface {
	CheckSecurityForSecurityUpdate() (string, error)
	GetCurrentPackageVersion(packageName string) (string, error)
	GetChangelogs(packageName string) (string, error)
}

func NewAptAction() AptAction {
	return &aptAction{}
}

type aptAction struct {
}

// CheckSecurityForSecurityUpdate implements AptAction.
func (a *aptAction) CheckSecurityForSecurityUpdate() (string, error) {
	grepCmd := exec.Command("grep", "security", "/etc/apt/sources.list")
	grepOut, err := grepCmd.Output()
	if err != nil {
		logger.GetLogger().Error("failed to get grep output")
	}

	if err := a.writeToFile("/tmp/security.list", grepOut); err != nil {
		logger.GetLogger().Error("failed writing security repo list to file", zap.Error(err))
	}

	upgradeCmd := exec.Command("apt-get", "upgrade", "-oDir::Etc::Sourcelist=/tmp/security.list", "-s")
	upgradeCmd.CombinedOutput()
	upgradeOut, err := upgradeCmd.CombinedOutput()
	if err != nil {
		logger.GetLogger().Error("failed to get security update", zap.Error(err))
	}

	return string(upgradeOut), nil
}

// GetChangelogs implements AptAction.
func (*aptAction) GetChangelogs(packageName string) (string, error) {
	changelogCmd := exec.Command("apt-get", "changelog", packageName)
	changelogOut, err := changelogCmd.Output()
	if err != nil {
		logger.GetLogger().Error("failed to get change log for a package", zap.Error(err), zap.String("package-name", packageName))
		return "", err
	}
	return string(changelogOut), nil
}

// GetCurrentPackageVersion implements AptAction.
func (*aptAction) GetCurrentPackageVersion(packageName string) (string, error) {

	dpkgCmd := exec.Command("dpkg-query", "-W", "-f", "${Version}", packageName)
	dpkgOut, err := dpkgCmd.Output()
	if err != nil {
		logger.GetLogger().Error("failed to get package Version", zap.String("package-name", packageName))
		return "", err
	}
	return string(dpkgOut), nil
}

func (*aptAction) writeToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}
