package internal

// BSS - basic service set
type BSS struct {
	BSSID        string
	Tags         map[string]bool
	Setups       []DBrecord
	ConnectedBSS map[string]bool
}

func newBSS(bssid string) BSS {
	b := new(BSS)
	b.BSSID = bssid
	b.Tags = make(map[string]bool)
	b.ConnectedBSS = make(map[string]bool)
	return *b
}

func (b *BSS) ingestRecord(r DBrecord) {
	// basic integrity check
	if r.BSSID != b.BSSID {
		return
	}

	bestIDs := findBestMatch(b.Setups, r)

	for _, id := range bestIDs {
		setup := b.Setups[id]
		if setup.merge(r) {
			b.Setups[id] = setup
		}
	}
	if len(bestIDs) == 0 {
		b.Setups = append(b.Setups, r)
	}

	// OLD CODE
	//// Remove refactor
	//
	//fullSetups := make(map[string]DBrecord)
	//hiddenSetups := make(map[string]DBrecord)
	//nullSetups := make(map[string]DBrecord)
	//
	//// Setup uniqueness is based on: BSSID, ESSID, AKM, Channel
	//// ToDo move to dbrecord method ?
	//key := calculateKey(r.BSSID,r.ESSID,r.AKM,strconv.Itoa(r.Channel))
	//
	//// null setup - zero channel, uptime, and power
	//if r.Channel == 0 || r.Power == 0 || r.Uptime == 0 {
	//	if oldR,ok := nullSetups[key]; ok {
	//		// merge records
	//		oldR.merge(r)
	//		nullSetups[key] = oldR
	//
	//	} else {
	//		nullSetups[key] = r
	//	}
	//
	//} else {
	//	// hidden setup - with empy bssid
	//	if r.ESSID == "" {
	//		if oldR,ok := hiddenSetups[key]; ok {
	//			// merge records
	//			oldR.merge(r)
	//			hiddenSetups[key] = oldR
	//
	//		} else {
	//			hiddenSetups[key] = r
	//		}
	//		// full setup
	//	} else {
	//		if oldR,ok := fullSetups[key]; ok {
	//			// merge records
	//			oldR.merge(r)
	//			fullSetups[key] = oldR
	//
	//		} else {
	//			fullSetups[key] = r
	//		}
	//	}
	//}
	//
	//
	//if r.BSSID == bssid {
	//
	//}
	//
	//
	//
	//// Merge all setups from db for given bssid
	//for _,r := range d.records {
	//
	//}
	//// Now merge incomplete setups into full and hidden
	//for _,n := range nullSetups {
	//	for idx,f := range fullSetups {
	//		merged := f.merge(n)
	//		if merged {
	//			fullSetups[idx] = f
	//		}
	//	}
	//	for idx,h := range hiddenSetups {
	//		merged := h.merge(n)
	//		if merged {
	//			hiddenSetups[idx] = h
	//		}
	//	}
	//}
	//
	//// Now merge hidden setups where possible, remove merged and keep the rest
	//for hkey,h := range hiddenSetups {
	//	for idx,f := range fullSetups {
	//		merged := f.merge(h)
	//		if merged {
	//			fullSetups[idx] = f
	//			delete(hiddenSetups,hkey)
	//		}
	//
	//	}
	//}
	//
	//
	//var setups []DBrecord
	//for _,s := range fullSetups {
	//	setups = append(setups,s)
	//}
	//for _,s := range hiddenSetups {
	//	setups = append(setups,s)
	//}
}

// Return list of indexes of elements in slice "setups" best matched for "record", at least one index in list is returned
func findBestMatch(setups []DBrecord, record DBrecord) (indexes []int) {
	indexValue := make(map[int]int)
	bestValue := 0

	for idx, s := range setups {
		// Set initial index value
		indexValue[idx] = 0

		// Check ESSID
		if s.ESSID == "" || record.ESSID == "" || s.ESSID == record.ESSID {
			indexValue[idx] += 1
		}

		// Check AKM
		if s.AKM == "" || record.AKM == "" || s.AKM == record.AKM {
			indexValue[idx] += 1
		}

		// Check Channel
		if s.Channel == 0 || record.Channel == 0 || s.Channel == record.Channel {
			indexValue[idx] += 1
		}

		// Check Encryptions
		if len(s.Encryptions) == 0 || len(record.Encryptions) == 0 {
			indexValue[idx] += 1
		} else {
			for enc := range s.Encryptions {
				if record.Encryptions[enc] {
					indexValue[idx] += 1
				}
			}
		}

		// Check Power
		if s.Power == 0 || record.Power == 0 {
			indexValue[idx] += 1
		}

		// Check Uptime
		if s.Uptime == 0 || record.Uptime == 0 {
			indexValue[idx] += 1
		}
	}

	// get best value
	for _, value := range indexValue {
		if value > bestValue {
			bestValue = value
		}
	}

	// 0 means no any mathches for merge are found
	if bestValue > 0 {
		// generate best indexes
		for idx, value := range indexValue {
			if value == bestValue {
				indexes = append(indexes, idx)
			}
		}
	}
	return indexes
}
