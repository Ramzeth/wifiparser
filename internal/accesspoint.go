package internal

// access point represents one exact AP device, which can have different settings over time, or possible evil-twins
type Accesspoint struct {
	Setups       []Setup
	BSSID        string
	Manufacturer string
}

func (a Accesspoint) valid() bool {
	if a.BSSID == "" {
		return false
	}
	return true
}

func (old *Accesspoint) merge(new Accesspoint) {
	// Check if it's basically the same networks
	if old.BSSID != new.BSSID {
		return
	}
	if old.Manufacturer == "" && new.Manufacturer != "" {
		old.Manufacturer = new.Manufacturer
	}

	// merge Setups
	// ToDo do it in separate function to reuse in analyze()
	for _, newSetup := range new.Setups {
		merged := false
		for idx, oldSetup := range old.Setups {
			merged = oldSetup.merge(newSetup)
			if merged {
				old.Setups[idx] = oldSetup
				break
			}
		}
		if !merged {
			// Add Setup to list, if it's not a simple client probe
			if newSetup.Power != 0 && newSetup.Uptime != 0 {
				old.Setups = append(old.Setups, newSetup)
			}
		}
	}
}
