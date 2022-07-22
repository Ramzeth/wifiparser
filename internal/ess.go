package internal

// ESS - extended service set
type ESS struct {
	ESSID        string
	BSSIDs       map[string]bool
	Tags         map[string]bool
	ConnectedESS map[string]bool
}

// TOdo remove refactor
//func(e *ESS) merge(newESS ESS) {
//	// basic integrity check
//	if e.ESSID != newESS.ESSID {
//		return
//	}
//	for _,newBSSID := range newESS.BSSIDs {
//		if !stringInSlice(newBSSID,e.BSSIDs) {
//			e.BSSIDs = append(e.BSSIDs, newBSSID)
//		}
//	}
//}

func (e *ESS) ingestRecord(r DBrecord) {
	// basic integrity check
	if e.ESSID != r.ESSID {
		return
	}
	e.BSSIDs[r.BSSID] = true
}

func newESS(essid string) ESS {
	e := new(ESS)
	e.ESSID = essid
	e.Tags = make(map[string]bool)
	e.BSSIDs = make(map[string]bool)
	e.ConnectedESS = make(map[string]bool)
	return *e
}
