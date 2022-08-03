package main

import (
	"encoding/xml"
	"github.com/Ramzeth/wifiparser/internal"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html/charset"
	"os"
	"strings"
)

type netXML struct {
	ESSID        ESSID    `xml:"SSID>essid"`
	Encryptions  []string `xml:"SSID>encryption"`
	BSSID        string   `xml:"BSSID"`
	Manufacturer string   `xml:"manuf"`
	Channel      int      `xml:"channel"`
	Power        int      `xml:"snr-info>max_signal_rssi"`
	Uptime       uint64   `xml:"bsstimestamp"`
	Location     string
}

type ESSID struct {
	Value    string `xml:",chardata"`
	Cloacked bool   `xml:"cloaked,attr"`
}

//Todo remove refactor
//func parseNetXMLstruct(n netXML) (net internal.ESS, ap internal.Accesspoint) {
//	// Get network (ESS) data
//	essid := strings.Replace(n.ESSID.Value, ";", "", -1)
//	if essid != "" {
//		net.ESSID = essid
//		net.BSSIDs = append(net.BSSIDs, n.BSSID)
//	}
//
//	// Get accesspoint data
//	ap.BSSID = n.BSSID
//
//	setup := new(internal.Setup)
//	setup.Encryptions = make(map[string]bool)
//
//
//	setup.ESSID = essid
//	setup.Channel = n.Channel
//	setup.Power = n.Power
//	setup.Uptime = n.Uptime
//	if len(n.Encryptions) > 0 {
//		for _, encryption := range n.Encryptions {
//			switch encryption {
//			case "WPA+MGT":
//				setup.AKM = "WPA-Enterprise"
//			case "WPA+SAE":
//				setup.Encryptions["WPA3"] = true
//			case "WPA+AES-CCM":
//				setup.Encryptions["WPA2"] = true
//			case "WPA+PSK":
//				if setup.AKM == "" {
//					setup.AKM = "WPA-PSK"
//				}
//			case "WPA+TKIP":
//				setup.Encryptions["WPA"] = true
//			case "WEP":
//				setup.AKM = "WEP"
//				setup.Encryptions["WEP"] = true
//			case "None":
//				// Ensure that encryption got from probed frame, not client request
//				if setup.Power != 0 && setup.Uptime != 0 {
//					setup.AKM = "Open"
//					setup.Encryptions["Open"] = true
//				}
//			default:
//				setup.AKM = "Not implemented"
//				setup.Encryptions["Not implemented"] = true
//			}
//		}
//	} else {
//		setup.AKM = "Unknown"
//		setup.Encryptions["Unknown"] = true
//	}
//	setup.Location = n.Location
//	ap.Manufacturer = n.Manufacturer
//	ap.Setups = append(ap.Setups, *setup)
//	return net,ap
//}

func parseNetXMLstruct2(n netXML) (record internal.DBrecord) {
	// Get network (ESS) data
	record = internal.NewDBrecord()
	essid := strings.Replace(n.ESSID.Value, ";", "", -1)
	record.ESSID = essid
	record.BSSID = n.BSSID
	record.Channel = n.Channel
	record.Power = n.Power
	record.Uptime = n.Uptime
	if len(n.Encryptions) > 0 {
		for _, encryption := range n.Encryptions {
			switch encryption {
			case "WPA+MGT":
				record.AKM = "WPA-Enterprise"
			case "WPA+SAE":
				record.Encryptions["WPA3"] = true
			case "WPA+AES-CCM":
				record.Encryptions["WPA2"] = true
			case "WPA+PSK":
				if record.AKM == "" {
					record.AKM = "WPA-PSK"
				}
			case "WPA+TKIP":
				record.Encryptions["WPA"] = true
			case "WEP":
				record.AKM = "WEP"
				record.Encryptions["WEP"] = true
			case "None":
				// Ensure that encryption got from probed frame, not client request
				if n.Power != 0 && n.Uptime != 0 {
					record.AKM = "Open"
					record.Encryptions["Open"] = true
				}
			default:
				record.AKM = "Not implemented"
				record.Encryptions["Not implemented"] = true
			}
		}
	} else {
		record.AKM = "Unknown"
		record.Encryptions["Unknown"] = true
	}
	record.Location = n.Location
	return record
}

//todo remove refactor
//func parseNetXMLFile(filename string, filepath string) ([]internal.ESS,[]internal.Accesspoint, error) {
//	var aps []internal.Accesspoint
//	var networks []internal.ESS
//	if strings.Contains(filename, ".netxml") {
//		xmlStream, err := os.Open(filepath)
//		if err != nil {
//			log.Debugf("Can't open file %v with error: %v", filename, err)
//			return nil,nil,err
//		}
//		defer xmlStream.Close()
//		decoder := xml.NewDecoder(xmlStream)
//		decoder.CharsetReader = charset.NewReaderLabel
//		decoder.Entity = nil
//		decoder.Strict = false
//		for {
//			token, _ := decoder.Token()
//			if token == nil {
//				break
//			}
//
//			switch se := token.(type) {
//			case xml.StartElement:
//				if se.Name.Local == "wireless-network" {
//					var n netXML
//					err := decoder.DecodeElement(&n, &se)
//					if err != nil {
//						log.Debugf("Can't decode element %v, file: %v, error: %v", se, filename, err)
//						continue
//					}
//					// Filter bad networks
//					if (len(n.Encryptions) == 0) && (n.Uptime == 0) {
//						continue
//					}
//					n.Location = strings.Split(filename, ".kismet.")[0]
//
//					net,ap := parseNetXMLstruct(n)
//					aps = append(aps,ap)
//					networks = append(networks,net)
//				}
//			}
//		}
//	}
//	return networks,aps,nil
//}

func parseNetXMLFile2(filename string, filepath string) ([]internal.DBrecord, error) {
	var records []internal.DBrecord
	if strings.Contains(filename, ".netxml") {
		xmlStream, err := os.Open(filepath)
		if err != nil {
			log.Debugf("Can't open file %v with error: %v", filename, err)
			return nil, err
		}
		defer xmlStream.Close()
		decoder := xml.NewDecoder(xmlStream)
		decoder.CharsetReader = charset.NewReaderLabel
		decoder.Entity = nil
		decoder.Strict = false
		for {
			token, _ := decoder.Token()
			if token == nil {
				break
			}

			switch se := token.(type) {
			case xml.StartElement:
				if se.Name.Local == "wireless-network" {
					var n netXML
					err := decoder.DecodeElement(&n, &se)
					if err != nil {
						log.Debugf("Can't decode element %v, file: %v, error: %v", se, filename, err)
						continue
					}
					// Filter bad networks
					if (len(n.Encryptions) == 0) && (n.Uptime == 0) {
						continue
					}
					n.Location = strings.Split(filename, ".kismet.")[0]

					record := parseNetXMLstruct2(n)
					records = append(records, record)
				}
			}
		}
	}
	return records, nil
}
