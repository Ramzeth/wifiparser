package internal

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
)

//Todo
// implement in memory sql database to speedup searches - https://github.com/hashicorp/go-memdb

// Set of networks (ESS), ESSID is used as a key
type Database struct {
	essMap  map[string]ESS
	bssMap  map[string]BSS
	records []DBrecord
}

func NewDatabase() Database {
	d := new(Database)
	d.essMap = make(map[string]ESS)
	d.bssMap = make(map[string]BSS)
	return *d
}

// Parse raw records list, and populate structured data in db
func (d *Database) Organize() {
	// Generate map for ESS in database
	for _, r := range d.records {
		// Populate ESS
		if e, ok := d.essMap[r.ESSID]; ok {
			e.ingestRecord(r)
			d.essMap[r.ESSID] = e
		} else {
			ess := newESS(r.ESSID)
			ess.ingestRecord(r)
			d.essMap[r.ESSID] = ess
		}

		// Populate BSS
		if b, ok := d.bssMap[r.BSSID]; ok {
			b.ingestRecord(r)
			d.bssMap[r.BSSID] = b
		} else {
			bss := newBSS(r.BSSID)
			bss.ingestRecord(r)
			d.bssMap[r.BSSID] = bss
		}
	}

	// Analyze connections between BSS
	for bssid, bss := range d.bssMap {
		// Similars, bssids with close MAC may be connected
		connectedMap := make(map[string]bool)
		similars := d.getSimilarBSSIDs(bssid)
		for _, sim := range similars {
			connectedMap[sim] = true
		}

		// Connected by same essid
		essids := make(map[string]bool)
		bsetups := d.GetBSSsetups(bssid)
		for _, bs := range bsetups {
			if bs.ESSID != "" {
				essids[bs.ESSID] = true
			}
		}
		for e := range essids {
			esetups := d.GetESSsetups(e)
			for _, es := range esetups {
				connectedMap[es.BSSID] = true
			}
		}

		for conBSS := range connectedMap {
			bss.ConnectedBSS[conBSS] = true
		}
		d.bssMap[bssid] = bss
	}

	// Analyze connections between ESS
	for essid, ess := range d.essMap {
		connectedMap := make(map[string]bool)
		// Check connected via each bssid in ESS
		bssids := d.GetBSSIDbyESS(ess.ESSID)
		for _, bssid := range bssids {
			if bss, ok := d.bssMap[bssid]; ok {
				for cb := range bss.ConnectedBSS {
					cbSetups := d.GetBSSsetups(cb)
					for _, cbs := range cbSetups {
						if cbs.ESSID != "" && cbs.ESSID != ess.ESSID {
							connectedMap[cbs.ESSID] = true
						}
					}
				}
			}
		}

		for conESS := range connectedMap {
			ess.ConnectedESS[conESS] = true
		}
		d.essMap[essid] = ess
	}

}

// add new record to a list
func (d *Database) AddRecord(newRecord DBrecord) {
	d.records = append(d.records, newRecord)
	log.Tracef("Record addded: %v", newRecord)
}

func (d *Database) GetRecordsNum() int {
	return len(d.records)
}

// Returns a list of unique ESSs in database
func (d *Database) GetESSIDs() []string {
	var essids []string
	for e := range d.essMap {
		essids = append(essids, e)
	}
	return essids
}

// Returns a list of unique BSSID in database
func (d *Database) GetBSSIDs() []string {
	var bssids []string
	for b := range d.bssMap {
		bssids = append(bssids, b)
	}
	return bssids
}

// Returns a list of unique BSS setups for given bsssid in database
func (d *Database) GetBSSsetups(bssid string) []DBrecord {
	if bss, ok := d.bssMap[bssid]; ok {
		return bss.Setups
	} else {
		return nil
	}
}

// Returns a list of bssids, of access points implementing given ESS
func (d *Database) GetBSSIDbyESS(essid string) (bssids []string) {
	if ess, ok := d.essMap[essid]; ok {
		for b := range ess.BSSIDs {
			bssids = append(bssids, b)
		}
	}
	return bssids
}

// Returns a list of unique AP setups for given ESSs, setup with maximum power is chosen
func (d *Database) GetESSsetups(essid string) (essSetups []DBrecord) {
	bssids := d.GetBSSIDbyESS(essid)
	for _, b := range bssids {
		// get unique list of setups for given bssid
		bSetups := d.GetBSSsetups(b)
		for _, s := range bSetups {
			if s.ESSID == essid {
				essSetups = append(essSetups, s)
			}
		}
	}
	return essSetups
}

// Get similar bssids
func (d *Database) getSimilarBSSIDs(bssid string) (similars []string) {
	allBSSIDs := d.GetBSSIDs()
	for _, b := range allBSSIDs {
		if b != bssid && similar(b, bssid) {
			similars = append(similars, b)
		}
	}
	return similars
}

// Returns a list of ESS tags, each tag describes ESS anomaly
func (d *Database) GetESStags(essid string) (tags []string) {
	// Multiple BSSIDS
	if essid != "" {
		bssids := d.GetBSSIDbyESS(essid)
		if len(bssids) > 1 && essid != "" {
			tags = append(tags, "Multiple BSS")
		}
	} else {
		tags = append(tags, "Hidden")
	}
	return tags
}

// Returns a list of BSS tags, each tag describes BSS anomaly
func (d *Database) GetBSStags(bssid string) (tags []string) {
	// Possible evil-twin for bss. If there is multiple setups on same bssid, it may be an multipleBSS evil twin
	bssSetups := d.GetBSSsetups(bssid)
	if len(bssSetups) > 1 {
		tags = append(tags, "Multiple BSS setups, possible twin")
	}
	// Similar BSSIDS
	similars := d.getSimilarBSSIDs(bssid)
	if len(similars) > 0 {
		tags = append(tags, fmt.Sprintf("Similars: %v", strings.Join(similars, ";")))
	}
	return tags
}

func (d *Database) GetConnectedESS(essid string) (connected []string) {
	if ess, ok := d.essMap[essid]; ok {
		for c := range ess.ConnectedESS {
			connected = append(connected, c)
		}
	}
	return connected

}

// ToDo remove - refactor
//func(d *Database) Analyze() {
//	// Set discovered ESS Setups
//	for key, ess := range d.Networks {
//		for _,bssid := range ess.BSSIDs {
//			if ap,ok := d.Accesspoints[bssid]; ok {
//				for _,setup := range ap.Setups {
//					if setup.ESSID == ess.ESSID {
//						// merge Setups
//						merged := false
//						for idx,oldSetup := range ess.Setups {
//							merged = oldSetup.merge(setup)
//							if merged {
//								ess.Setups[idx] = oldSetup
//								break
//							}
//						}
//						if !merged {
//							ess.Setups = append(ess.Setups, setup)
//						}
//					}
//				}
//			}
//		}
//		d.Networks[key] = ess
//	}
//
//	// set ESS tags
//	for key, ess := range d.Networks {
//		if ess.Tags == nil {
//			ess.Tags = make(map[string]bool)
//		}
//		if len(ess.BSSIDs) > 1 {
//			ess.Tags["multipleBSS"] = true
//		}
//		if len(ess.Setups) > 1 {
//			ess.Tags["possibleTwin"] = true
//		}
//		d.Networks[key] = ess
//	}
//}

//TODO remove refactor
// ingest new ESSID to a list
//func(d *Database) ingestESS(newEss ESS) {
//	// If ess is already in a list
//	id := newEss.ESSID
//	if oldEss, ok := d.Networks[id]; ok {
//		oldEss.merge(newEss)
//		d.Networks[id] = oldEss
//	} else {
//		if id != "" {
//			d.Networks[id] = newEss
//		}
//	}
//}

// ingest new ap to a list
// Todo remove refactor
//func(d *Database) IngestAP(newAP Accesspoint) {
//	id := newAP.BSSID
//	// Basic integrity check
//	if !newAP.valid()  {
//		return
//	}
//
//	// If ap is already in a list
//	if oldAP, ok := d.Accesspoints[id]; ok {
//		oldAP.merge(newAP)
//		d.Accesspoints[id] = oldAP
//	} else {
//		d.Accesspoints[id] = newAP
//	}
//}
