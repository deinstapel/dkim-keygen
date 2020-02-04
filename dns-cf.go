package main

import (
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var cfAPI *cloudflare.API
var cfZoneCache map[string]string = map[string]string{}
var cfLog = logrus.WithField("module", "dns-cf")

func buildCfAPI() error {
	api, err := cloudflare.NewWithAPIToken(viper.GetString("CF_API_KEY"))
	if err != nil {
		return err
	}
	cfAPI = api
	return nil
}

// Retrieve a zone id from the cloudflare API or from the cache. Cache is preferred
func getZoneID(zone string) (string, error) {
	if z, ok := cfZoneCache[zone]; ok {
		return z, nil
	}
	z, err := cfAPI.ZoneIDByName(zone)
	if err == nil {
		cfLog.WithFields(logrus.Fields{
			"zone": zone,
			"id":   z,
		}).Debug("resolved zone")
		cfZoneCache[zone] = z
	}
	return z, err
}

func updateRecords(entries map[string]domainConfig) {
	for domain, entry := range entries {
		zoneLog := cfLog.WithField("zone", domain)
		zoneID, err := getZoneID(domain)
		if err != nil {
			zoneLog.WithError(err).Warn("Zone not managed or CF API unavailable")
			continue
		}
		rec := cloudflare.DNSRecord{
			Type: "TXT",
			Name: fmt.Sprintf("mail._domainkey.%s", domain),
		}
		record, err := cfAPI.DNSRecords(zoneID, rec)
		if err != nil {
			zoneLog.WithError(err).Warn("Error querying DNS records")
			continue
		}
		rec.Content = entry.txt
		if len(record) > 1 {
			zoneLog.Warn("More than one record found, please cleanup manually")
			continue
		}
		if len(record) == 1 && record[0].Content == entry.txt {
			zoneLog.Debug("Skipping update")
			continue
		}
		if len(record) == 0 {
			if _, err := cfAPI.CreateDNSRecord(zoneID, rec); err != nil {
				zoneLog.WithError(err).Warn("Failed to create DNS Record")
			}
		} else {
			if err := cfAPI.UpdateDNSRecord(zoneID, record[0].ID, rec); err != nil {
				zoneLog.WithError(err).Warn("Failed to update DNS Record")
			}
		}
	}
}
