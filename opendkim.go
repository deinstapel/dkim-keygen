package main

/**
* This file generates OpenDKIM configuration files for the generated domain keys.
 */

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"syscall"

	"github.com/mitchellh/go-ps"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var dkimLog = logrus.WithField("module", "opendkim")

func generateOpenDKIMConfig(records map[string]domainConfig) {
	keyTableContents := ""
	signingTableContents := ""
	openDkimConfigDir := viper.GetString("TARGET_PATH")

	for domain, config := range records {
		keyTableContents += fmt.Sprintf("mail._domainkey.%[1]s %[1]s:mail:%[2]s\n", domain, config.privPath)
		signingTableContents += fmt.Sprintf("*@%[1]s mail._domainkey.%[1]s\n", domain)
	}
	dkimLog.Info("Generated config files, persisting to disk")
	if e := ioutil.WriteFile(path.Join(openDkimConfigDir, "KeyTable"), []byte(keyTableContents), 0600); e != nil {
		dkimLog.WithError(e).Error("Failed to write KeyTable")
		return
	}
	if e := ioutil.WriteFile(path.Join(openDkimConfigDir, "SigningTable"), []byte(signingTableContents), 0600); e != nil {
		dkimLog.WithError(e).Error("Failed to write SigningTable")
		return
	}
	dkimLog.Debug("Reloading OpenDKIM")
	proc, err := ps.Processes()
	if err != nil {
		dkimLog.WithError(err).Warning("Failed to reload OpenDKIM, please reload manually")
		return
	}
	sent := false
	for _, p := range proc {
		if strings.Contains(p.Executable(), "opendkim") {
			if err := syscall.Kill(p.Pid(), syscall.SIGUSR1); err != nil {
				dkimLog.WithError(err).Warning("Failed to send SigUSR1 to openDKIM, please reload manually")
				continue
			}
			sent = true
		}
	}
	if !sent {
		dkimLog.Warning("No running OpenDKIM binary found")
	}
}
