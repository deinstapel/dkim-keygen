package main

/**
 * This file is responsible to generate the RSA key pairs and the TXT record files
 */

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var keygenLog = logrus.WithField("module", "keygen")
var reader = rand.Reader

const bitSize = 2048

type domainConfig struct {
	key      *rsa.PrivateKey
	pub      *rsa.PublicKey
	privPath string
	pubPath  string
	txtPath  string
	txt      string
}

func processDomains(domains domainKeySet) map[string]domainConfig {
	res := make(map[string]domainConfig, len(domains))
	for domain := range domains {
		domLog := keygenLog.WithField("domain", domain)
		domLog.Debug("Processing DKIM keys")

		// OpenDKIM expects both of these files to be pem encoded, I think?
		privkeyFile := path.Join(viper.GetString("TARGET_PATH"), domain, "mail.private")
		pubkeyFile := path.Join(viper.GetString("TARGET_PATH"), domain, "mail.public")
		recordFile := path.Join(viper.GetString("TARGET_PATH"), domain, "mail.txt")
		var priv *rsa.PrivateKey
		var pub *rsa.PublicKey

		if err := os.MkdirAll(path.Join(viper.GetString("TARGET_PATH"), domain), 0770); err != nil {
			domLog.WithError(err).Error("Could not create key directory")
			continue
		}

		if _, err := os.Stat(privkeyFile); os.IsNotExist(err) {
			domLog.Info("private key not found, generating key pair")
			priv, pub = GenerateRsaKeyPair(bitSize)
			privContents := ExportRsaPrivateKeyAsPemStr(priv)
			if e := ioutil.WriteFile(privkeyFile, []byte(privContents), 0660); e != nil {
				domLog.WithError(e).Error("Failed to write private key")
				continue
			}
		} else if content, err := ioutil.ReadFile(privkeyFile); err != nil {
			domLog.WithError(err).Error("Failed to read private key, check permissions")
			continue
		} else if decodedPriv, err := ParseRsaPrivateKeyFromPemStr(string(content)); err != nil {
			domLog.WithError(err).Error("Failed to decode private key, unknown format")
			continue
		} else {
			priv = decodedPriv
		}

		if pub == nil {
			pub = &priv.PublicKey
		}
		if pubContents, e := ExportRsaPublicKeyAsPemStr(pub); e != nil {
			domLog.WithError(e).Error("Failed to export public key")
			continue
		} else if e := ioutil.WriteFile(pubkeyFile, []byte(pubContents), 0600); e != nil {
			domLog.WithError(e).Error("Failed to write public key")
			continue
		}

		if pubKeyFoo, e := ExportPubKeyBase64(pub); e != nil {
			domLog.WithError(e).Error("Failed to write record file")
			continue
		} else {
			recordContents := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubKeyFoo)
			if e := ioutil.WriteFile(recordFile, []byte(recordContents), 0600); e != nil {
				domLog.WithError(e).Error("Failed to write record file")
				continue
			}

			res[domain] = domainConfig{
				key:      priv,
				pub:      pub,
				txt:      recordContents,
				privPath: privkeyFile,
				pubPath:  pubkeyFile,
				txtPath:  recordFile,
			}
		}
	}
	return res
}
