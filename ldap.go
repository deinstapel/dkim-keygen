package main

/**
 * This file defines the interaction with the LDAP server to fetch domains from.
 */

import (
	"context"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"

	"github.com/spf13/viper"
)

type domainKeySet map[string]bool

var pkgLog = logrus.WithField("module", "ldap")

func queryLdap() (*ldap.SearchResult, error) {
	ldapConn, err := ldap.DialURL(viper.GetString("LDAP_SERVER"))
	if err != nil {
		pkgLog.WithError(err).Error("LDAP Connection failed")
		return nil, err
	}
	defer ldapConn.Close()

	if viper.GetString("LDAP_BIND_USER") != "" && viper.GetString("LDAP_BIND_PASS") != "" {
		pkgLog.Debug("Trying LDAP bind...")
		if err := ldapConn.Bind(viper.GetString("LDAP_BIND_USER"), viper.GetString("LDAP_BIND_PASS")); err != nil {
			pkgLog.WithError(err).Error("Bind failed, possibly invalid credentials")
			return nil, err
		}
		pkgLog.Info("LDAP bind OK")
	}

	userBaseDn := viper.GetString("LDAP_USER_BASE_DN")
	userFilter := viper.GetString("LDAP_USER_FILTER")
	attributes := viper.GetStringSlice("LDAP_MAIL_ATTRIBUTES")
	result, err := ldapConn.Search(ldap.NewSearchRequest(
		userBaseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userFilter,
		attributes,
		nil,
	))
	pkgLog.WithFields(logrus.Fields{
		"err": err,
	}).Debug("Query finished")
	return result, err
}

func startLdapSync(c context.Context) (chan domainKeySet, error) {
	results := make(chan domainKeySet, 1)

	syncInterval, err := time.ParseDuration(viper.GetString("LDAP_SYNC_INTERVAL"))
	if err != nil {
		pkgLog.WithError(err).Error("LDAP Sync Interval invalid")
		return nil, err
	}

	t := time.NewTicker(syncInterval)
	go func() {
		<-c.Done()
		t.Stop()
	}()
	go func() {
		pkgLog.Debug("Starting group sync")
		defer pkgLog.Debug("Group sync exit")

		// https://github.com/golang/go/issues/17601#issuecomment-311955879
		for ; true; <-t.C {
			pkgLog.Debug("Group Sync Iteration")
			result, err := queryLdap()
			if err != nil {
				pkgLog.WithError(err).Error("Search failed, closing result chan and ticker")
				close(results)
				t.Stop()
				return
			}

			domains := make(domainKeySet)
			for _, e := range result.Entries {
				for _, attr := range e.Attributes {
					for _, attrValue := range attr.Values {
						emailParts := strings.Split(attrValue, "@")
						if len(emailParts) < 2 {
							pkgLog.WithFields(logrus.Fields{
								"dn":   e.DN,
								"attr": attr.Name,
								"addr": attrValue,
							}).Warning("Mail without domain detected")
							continue
						}
						domains[emailParts[1]] = true
					}
				}
			}
			pkgLog.WithField("domainCount", len(domains)).Debug("Scan finished")
			results <- domains
		}
	}()
	return results, nil
}
