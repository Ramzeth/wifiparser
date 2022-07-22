package internal

// Setup is exact AP setting, normally it's only one Setup for ap. Different Setups shows possible evil-twins
type Setup struct {
	ESSID       string
	AKM         string
	Channel     int
	Encryptions map[string]bool
	Power       int
	Location    string
	Uptime      uint64
	WPS         string
}

// Merge updates Setup with additional data if Setups has the same fingerpring: AKM, Channel, ESSID (if not hidden)
func (old *Setup) merge(new Setup) bool {
	// Same Channel means the same possible Setups - trying to merge.
	if old.Channel == new.Channel {
		// ESSID
		if old.ESSID != new.ESSID {
			// different non empty essids not merged
			if old.ESSID != "" && new.ESSID != "" {
				return false
			}
			// update empty ESSID with anything
			if old.ESSID == "" {
				old.ESSID = new.ESSID
			}
		}

		// AKM
		if old.AKM != new.AKM {
			// different akms not merged
			if old.AKM != "" && new.AKM != "" {
				return false
			}
			// update empty AKM with anything
			if old.AKM == "" {
				old.AKM = new.AKM
			}
		}

		// Check Encryptions, just add any new discovered encryption
		for newEnc := range new.Encryptions {
			old.Encryptions[newEnc] = true
		}

		// Power
		if (old.Power < new.Power && new.Power != 0) || (old.Power == 0) {
			old.Power = new.Power
			old.Location = new.Location
		}

		// Uptime
		if old.Uptime < new.Uptime {
			old.Uptime = new.Uptime
		}

		// WPS
		// ToDo check for locked status  and so on
		if new.WPS != "" {
			old.WPS = new.WPS
		}

		//ToDO refactor
		//// If old Setup is an empty (eg. from client probe)
		//} else if old.Uptime == 0 && old.Power == 0 {
		//	// If Setups have different essids, and old is not hidden, they different and not merged
		//	if old.ESSID != new.ESSID && old.ESSID != "" {
		//		return false
		//	}
		//	// Update old ESSID, and unhide it
		//	if new.ESSID != "" {
		//		old.ESSID = new.ESSID
		//		old.hidden = false
		//	}
		//	// Update Encryptions
		//	for encryption := range new.Encryptions {
		//		old.Encryptions[encryption] = true
		//	}
		//	// there is no Power in empty Setup, just set it
		//	if new.Power != 0 {
		//		old.Power = new.Power
		//		old.Location = new.Location
		//	}
		//	// update Uptime, set the oldest one
		//	if old.Uptime < new.Uptime {
		//		old.Uptime = new.Uptime
		//	}
		//// If new Setup is an empty (eg. from client probe), update bssid if possible
		//} else if new.Power == 0 && new.Uptime == 0 {
		//	if new.ESSID != "" && old.ESSID == "" {
		//		old.ESSID = new.ESSID
		//		old.hidden = false
		//	}
	} else {
		return false
	}
	return true
}

// calculate uniq network hashkey, if there is not enough parameters to generate a key, network treats as incomplete
// TODO remove
//func(n network) calculateKey() (complete bool,key uint32) {
//	complete = true
//	var concat []byte
//
//	// ESSID, seems it's a problem to merge into hidden network if ESSID is used as a key
//	//if n.ESSID == "" && !n.hidden {
//	//	complete = false
//	//}
//	//if n.hidden {
//	//	concat = append(concat, []byte("hidden")...)
//	//} else {
//	//	concat = append(concat, []byte(n.ESSID)...)
//	//}
//
//	// BSSID
//	if n.bssid == "" {
//		complete = false
//	}
//	concat = append(concat, []byte(n.bssid)...)
//
//	// ENCRYTPTIONS
//	if len(n.Encryptions) == 0 {
//		complete = false
//	}
//	for _, e := range n.Encryptions {
//		concat = append(concat, []byte(e)...)
//	}
//
//	// AKM
//	if n.AKM == "" {
//		complete = false
//	}
//	concat = append(concat, []byte(n.AKM)...)
//
//	// CHANNEL
//	if n.Channel == 0 {
//		complete = false
//	}
//	concat = append(concat, byte(n.Channel))
//
//	key = crc32.ChecksumIEEE(concat)
//	return complete,key
//}
