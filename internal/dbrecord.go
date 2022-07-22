package internal

import "hash/crc32"

type DBrecord struct {
	ESSID       string
	BSSID       string
	AKM         string
	Channel     int
	Encryptions map[string]bool
	Power       int
	Location    string
	Uptime      uint64
	WPS         string
}

// todo seems unused
func (r DBrecord) calculateKey() (key uint32) {
	var concat []byte
	concat = append(concat, []byte(r.ESSID)...)
	concat = append(concat, []byte(r.BSSID)...)
	concat = append(concat, []byte(r.AKM)...)
	concat = append(concat, byte(r.Channel))
	for e := range r.Encryptions {
		concat = append(concat, []byte(e)...)
	}
	concat = append(concat, byte(r.Power))
	concat = append(concat, []byte(r.Location)...)
	concat = append(concat, byte(r.Uptime))
	concat = append(concat, []byte(r.WPS)...)
	key = crc32.ChecksumIEEE(concat)
	return key
}

func NewDBrecord() DBrecord {
	r := new(DBrecord)
	r.Encryptions = make(map[string]bool)
	return *r
}

func (old *DBrecord) merge(new DBrecord) bool {
	// Check if it's different records
	if differs(old.ESSID, new.ESSID) || differs(old.BSSID, new.BSSID) || differs(old.Channel, new.Channel) || differs(old.AKM, new.AKM) {
		return false
	}

	// update empty ESSID with anything
	if old.ESSID == "" {
		old.ESSID = new.ESSID
	}

	// update empty AKM with anything
	if old.AKM == "" {
		old.AKM = new.AKM
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
	return true
}
