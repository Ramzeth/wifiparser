package main

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"wifiparser/internal"
)

//ToDO remove

//func outBSSs(db internal.Database,w io.Writer)  {
//	csvWriter := csv.NewWriter(w)
//	defer csvWriter.Flush()
//	header := []string{"ESSID", "Description", "BSSID", "AKM", "Encryption", "Channel", "Power", "Manufacturer", "Uptime", "Location", "WPS"}
//	csvWriter.Write(header)
//	// Output data for non hidden ESS
//	for _, ess := range db.Networks {
//		writeESSID := ess.ESSID
//		tags := make(map[string]bool)
//		// Generate description tags
//		if len(ess.BSSIDs) > 1 {
//			tags["multipleBSS"] = true
//		}
//		for _,bssid := range ess.BSSIDs {
//			writeBSSID := bssid
//			ap,ok := db.Accesspoints[bssid]
//			// if there is ap for given essid in db
//			if ok {
//				if len(ap.Setups) > 1 {
//					tags["possibleTwin"] = true
//				} else {
//					delete(tags,"possibleTwin")
//				}
//				for _,setup := range ap.Setups {
//					if setup.ESSID == ess.ESSID {
//						writeAKM := setup.AKM
//						var encs []string
//						for e :=range setup.Encryptions {
//							encs = append(encs,e)
//						}
//						writeEncryption := strings.Join(encs,"/")
//						var descriptions []string
//						for t := range tags {
//							descriptions = append(descriptions,t)
//						}
//						writeDescription := strings.Join(descriptions,";")
//						writeChannel := strconv.Itoa(setup.Channel)
//						writePower := strconv.Itoa(setup.Power)
//						writeManufacturer := ap.Manufacturer
//						writeUptime := parsedTime(setup.Uptime)
//						writeLocation := setup.Location
//						writeWPS := setup.WPS
//						record := []string{writeESSID, writeDescription, writeBSSID, writeAKM, writeEncryption, writeChannel, writePower, writeManufacturer, writeUptime, writeLocation, writeWPS}
//						csvWriter.Write(record)
//					}
//				}
//			}
//		}
//	}
//	// Output data for hidden ESS
//	for _, ap := range db.Accesspoints {
//		tags := make(map[string]bool)
//		writeBSSID := ap.BSSID
//		for _,setup := range ap.Setups {
//			if setup.ESSID == "" {
//				writeESSID := setup.ESSID
//				writeAKM := setup.AKM
//				var encs []string
//				for e :=range setup.Encryptions {
//					encs = append(encs,e)
//				}
//				writeEncryption := strings.Join(encs,"/")
//				var descriptions []string
//				for t := range tags {
//					descriptions = append(descriptions,t)
//				}
//				writeDescription := strings.Join(descriptions,";")
//				writeChannel := strconv.Itoa(setup.Channel)
//				writePower := strconv.Itoa(setup.Power)
//				writeManufacturer := ap.Manufacturer
//				writeUptime := parsedTime(setup.Uptime)
//				writeLocation := setup.Location
//				writeWPS := setup.WPS
//				record := []string{writeESSID, writeDescription, writeBSSID, writeAKM, writeEncryption, writeChannel, writePower, writeManufacturer, writeUptime, writeLocation, writeWPS}
//				csvWriter.Write(record)
//			}
//		}
//	}
//}

func outESS(db internal.Database, w io.Writer) {
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()
	header := []string{"ESSID", "Anomaly", "Connected ESS", "AKM", "Encryption", "Uptime", "Location", "WPS"}
	csvWriter.Write(header)
	// Output data for non hidden ESS
	essList := db.GetESSIDs()
	for _, ess := range essList {
		if ess == "" {
			continue
		}
		tagList := db.GetESStags(ess)
		setups := db.GetESSsetups(ess)
		// Now trying to collapse different setups data for one ess
		akmMap := make(map[string]bool)
		encMap := make(map[string]bool)
		wpsMap := make(map[string]bool)
		var maxUptime uint64
		bestLocation := ""
		for _, s := range setups {
			tagList = append(tagList, db.GetBSStags(s.BSSID)...)
			akmMap[s.AKM] = true
			for e := range s.Encryptions {
				encMap[e] = true
			}
			if s.Uptime > maxUptime {
				maxUptime = s.Uptime
				bestLocation = s.Location
			}
			wpsMap[s.WPS] = true
		}
		var akmList []string
		var encList []string
		var wpsList []string
		for a := range akmMap {
			akmList = append(akmList, a)
		}
		for e := range encMap {
			encList = append(encList, e)
		}
		for w := range wpsMap {
			wpsList = append(wpsList, w)
		}

		// Write ess data
		essAnomaly := strings.Join(tagList, ";")
		connected := strings.Join(db.GetConnectedESS(ess), ";")
		akm := strings.Join(akmList, "/")
		encryption := strings.Join(encList, "/")
		wps := strings.Join(wpsList, "/")
		record := []string{ess, essAnomaly, connected, akm, encryption, parsedTime(maxUptime), bestLocation, wps}
		csvWriter.Write(record)
	}
}

func outBSS(db internal.Database, w io.Writer) {
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()
	header := []string{"ESSID", "BSSID", "ESS anomaly", "BSS anomaly", "AKM", "Encryption", "Channel", "Power", "Uptime", "Location", "WPS"}
	csvWriter.Write(header)
	bssids := db.GetBSSIDs()
	for _, bssid := range bssids {
		for _, setup := range db.GetBSSsetups(bssid) {
			var encs []string
			for e := range setup.Encryptions {
				encs = append(encs, e)
			}
			writeEncryption := strings.Join(encs, "/")
			bssTags := db.GetBSStags(setup.BSSID)
			bssAnomaly := strings.Join(bssTags, ";")
			essTags := db.GetESStags(setup.ESSID)
			essAnomaly := strings.Join(essTags, ";")
			record := []string{setup.ESSID, setup.BSSID, essAnomaly, bssAnomaly, setup.AKM, writeEncryption, strconv.Itoa(setup.Channel), strconv.Itoa(setup.Power), parsedTime(setup.Uptime), setup.Location, setup.WPS}
			csvWriter.Write(record)
		}
	}
}

//func outAPs(db internal,w io.Writer)  {
//	csvWriter := csv.NewWriter(w)
//	defer csvWriter.Flush()
//	header := []string{"ESSID", "Description", "BSSID", "AKM", "Encryption", "Channel", "Power", "Manufacturer", "Uptime", "Location", "WPS"}
//	csvWriter.Write(header)
//
//}
