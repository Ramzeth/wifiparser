package main

import (
	"encoding/xml"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html/charset"
	"hash/crc32"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
)

type WirelessNetworkT struct {
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

type networkT struct {
	essid        string
	hidden       string
	bssid        string
	protocol     string
	auth         string
	manufacturer string
	channel      int
	power        int
	uptime       string
	location     string
	wps          string
}

func parsedTime(timestamp uint64) string {
	secondsTotal := int64(time.Duration(timestamp * 1000).Seconds())
	days, remainder := secondsTotal/(60*60*24), secondsTotal%(60*60*24)
	hours, remainder := remainder/(60*60), remainder%(60*60)
	minutes, seconds := remainder/(60), remainder%(60)

	return fmt.Sprintf("%vd:%vh:%vm:%vs", days, hours, minutes, seconds)
}

func parseNetwork(n WirelessNetworkT) (result networkT) {
	result.essid = strings.Replace(n.ESSID.Value, ";", "", -1)
	if n.ESSID.Cloacked {
		result.hidden = "Hidden"
	}
	result.bssid = n.BSSID
	if len(n.Encryptions) > 0 {
		for _, encryption := range n.Encryptions {
			switch encryption {
			case "WPA+MGT":
				result.auth = "WPA-Enterprise"
			case "WPA+AES-CCM":
				result.protocol = result.protocol + "/WPA2"
			case "WPA+PSK":
				if result.auth == "" {
					result.auth = "WPA-PSK"
				}
			case "WPA+TKIP":
				result.protocol = result.protocol + "/WPA"
			case "WEP":
				result.auth = "WEP"
				result.protocol = "WEP"
			case "None":
				result.protocol = "/Open"
				result.auth = "Open"
			default:
				result.protocol = "/Not implemented"
				result.auth = "Not implemented"
			}
		}
		result.protocol = result.protocol[1:]
	} else {
		result.protocol = "Unknown"
		result.auth = "Unknown"
	}
	result.manufacturer = n.Manufacturer
	result.channel = n.Channel
	result.power = n.Power
	result.uptime = parsedTime(n.Uptime)
	result.location = strings.Split(n.Location, ".kismet.")[0]
	return result
}

func main() {
	// Set logging level
	log.SetLevel(log.ErrorLevel)
	log.Debug("start")

	// read files from local dir
	var files, err = ioutil.ReadDir(".")
	if err != nil {
		log.Fatalf("Unable to read from local dir: %v", err)
	}

	// Init network list
	networks := make(map[uint32]networkT)
	networksWPS := make(map[string]string)

	for _, f := range files {
		// parse all .netxml files and generate networks map
		if strings.Contains(f.Name(), ".netxml") {
			xmlStream, err := os.Open(path.Join("./", f.Name()))
			if err != nil {
				log.Debugf("Can't open file %v with error: %v", f.Name(), err)
				return
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
						var n WirelessNetworkT
						err := decoder.DecodeElement(&n, &se)
						if err != nil {
							log.Debugf("Can't decode element %v, file: %v, error: %v", se, f.Name(), err)
							continue
						}
						// Filter bad networks
						if (len(n.Encryptions) == 0) && (n.Uptime == 0) {
							continue
						}

						n.Location = f.Name()
						// calculate uniq network hashkey
						var concat []byte
						concat = append(concat, []byte(n.ESSID.Value)...)
						concat = append(concat, []byte(n.BSSID)...)
						for _, e := range n.Encryptions {
							concat = append(concat, []byte(e)...)
						}
						concat = append(concat, byte(n.Channel))
						key := crc32.ChecksumIEEE(concat)
						if pn, ok := networks[key]; ok {
							if ((pn.power < n.Power) && (n.Power != 0)) || (pn.power == 0) {
								networks[key] = parseNetwork(n)
							}
						} else {
							networks[key] = parseNetwork(n)
						}
					}
				}
			}
			// parse all .cap files and get WPS
		} else if strings.Contains(f.Name(), ".cap") {
			handle, err := pcap.OpenOffline(path.Join("./", f.Name()))
			if err != nil {
				log.Errorf("can't open .cap file %v, with error: %v", f.Name(), err)
			}
			defer handle.Close()

			// Loop through packets in file
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				dot11 := packet.Layer(layers.LayerTypeDot11)
				if nil != dot11 {
					dot11, _ := dot11.(*layers.Dot11)
					ok, b, data := Dot11ParseWPS(packet, dot11)
					bssid := strings.ToUpper(b.String())
					if ok {
						if networksWPS[bssid] == "Locked" {
							continue
						} else if data["AP Setup Locked"] != "" {
							networksWPS[bssid] = "Locked"
						} else {
							networksWPS[bssid] = data["Version"]
						}
					}
				}
			}
		}
	}

	//generate output
	fmt.Println("ESSID;Hidden;BSSID;Protocol;Auth;Channel;Power;Manufacturer;Uptime;Location;WPS")
	for _, n := range networks {
		n.wps = networksWPS[n.bssid]
		fmt.Printf("%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v\n", n.essid, n.hidden, n.bssid, n.protocol, n.auth, n.channel, n.power, n.manufacturer, n.uptime, n.location, n.wps)
	}
}
