package main

/**
 * This file defines the entry point to the application,
 * calling into the LDAP server and processing the results.
 * The basic procesing flow looks like this:
 * /-------------\      /------------\      /------------\
 * |    Timer    | ---> |    LDAP    | ---> |   Keygen   |
 * \-------------/      \------------/      \------------/
 *                                         /      |
 *                                        V       V
 *                           /------------\ /------------\
 *                 CF   <--- |    DNS     | |  OpenDKIM  |
 *                           \------------/ \------------/
 */

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	viper.SetEnvPrefix("DKIM_KEYGEN")
	viper.AutomaticEnv()
	if viper.GetBool("DEBUG") {
		log.SetLevel(log.DebugLevel)
	}
	log.Info("Starting DKIM Keygen")
	log.SetFormatter(&log.TextFormatter{})

	ctx, cancel := context.WithCancel(context.Background())
	canceled := false
	results, err := startLdapSync(ctx)
	if err != nil {
		os.Exit(1)
	}
	if err := buildCfAPI(); err != nil {
		log.WithError(err).Error("Failed to initialize cloudflare DNS API")
		os.Exit(1)
	}
	go func() {
		for domains := range results {
			for k := range domains {
				log.Infof("Found DKIM domain: '%v'", k)
			}
			domResp := processDomains(domains)
			generateOpenDKIMConfig(domResp)
			updateRecords(domResp)
			log.Info("Processing done")
		}
		log.Infof("Terminating result printer")
		if !canceled {
			os.Exit(1)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	<-sigs
	canceled = true
	cancel()
}
