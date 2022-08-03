package main

import (
	"flag"
	"fmt"
	"github.com/Ramzeth/wifiparser/internal"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func parsedTime(timestamp uint64) string {
	secondsTotal := int64(time.Duration(timestamp * 1000).Seconds())
	days, remainder := secondsTotal/(60*60*24), secondsTotal%(60*60*24)
	hours, remainder := remainder/(60*60), remainder%(60*60)
	minutes, seconds := remainder/(60), remainder%(60)
	return fmt.Sprintf("%vd:%vh:%vm:%vs", days, hours, minutes, seconds)
}

func main() {
	var debugLevelFlag = flag.Bool("v", false, "enable debug logs")
	var traceLevelFlag = flag.Bool("vv", false, "enable debug and trace logs")
	flag.PrintDefaults()
	flag.Parse()
	//set log level
	if *debugLevelFlag {
		log.SetLevel(log.DebugLevel)
	}
	if *traceLevelFlag {
		log.SetLevel(log.TraceLevel)
	}

	log.Debug("start")

	// read files from current dir
	//ToDo remove, set parameter for dir to parse files inside
	rootPath := "./"
	//var currentDir, err = ioutil.ReadDir(".")
	//if err != nil {
	//	log.Fatalf("Unable to read from local dir: %v", err)
	//}

	// Init network list
	db := internal.NewDatabase()
	//db.networks = make(map[string]internal.ess)
	//db.accesspoints = make(map[string]internal.accesspoint)

	//Walking all the file root
	//ToDo move to some input
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// parse all .netxml files and generate networks map
			//todo return back or remove
			//tempESSs, tempAPs, err := parseNetXMLFile(info.Name(), path)

			//if err != nil {
			//	return err
			//}
			//for _, tempESS := range tempESSs {
			//
			//	//db.ingestESS(tempESS)
			//}
			//for _, tempAP := range tempAPs {
			//	db.ingestAP(tempAP)
			//}

			//populate dbrecords
			records, err := parseNetXMLFile2(info.Name(), path)
			if err != nil {
				return err
			}
			for _, r := range records {
				db.AddRecord(r)
			}

			// parse all .cap files and get WPS
			if strings.Contains(info.Name(), ".cap") {
				handle, err := pcap.OpenOffline(path)
				if err != nil {
					log.Errorf("can't open .cap file %v, with error: %v", info.Name(), err)
				}
				defer handle.Close()

				// Loop through packets in file
				packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packetSource.Packets() {
					dot11 := packet.Layer(layers.LayerTypeDot11)
					if nil != dot11 {
						dot11, _ := dot11.(*layers.Dot11)
						ok, b, data := Dot11ParseWPS(packet, dot11)
						if ok {
							// Update data with wps
							//newAP := new(internal.Accesspoint)
							//newAP.BSSID = strings.ToUpper(b.String())
							//newSetup := new(internal.Setup)
							//if data["AP Setup Locked"] != "" {
							//	newSetup.WPS = "Locked"
							//} else {
							//	newSetup.WPS = data["Version"]
							//}

							// Update data with wps 2
							r := internal.NewDBrecord()
							r.BSSID = strings.ToUpper(b.String())
							if data["AP Setup Locked"] != "" {
								r.WPS = "Locked"
							} else {
								r.WPS = data["Version"]
							}
							db.AddRecord(r)
						}

						// Parse EAP
						ok, info := ParseEAP(packet)
						if ok {
							r := internal.NewDBrecord()
							// ToDo check valid mac address, ap or supplicant ?
							r.BSSID = strings.ToUpper(dot11.Address3.String())
							for _, e := range info.EAPtypes {
								switch e {
								case 1:
								case 13:
									r.Encryptions["EAP-TLS"] = true
								default:
									r.Encryptions[fmt.Sprintf("EAP: %v", e)] = true
								}

							}
							db.AddRecord(r)
							log.Tracef("Found EAP - BSSID: %v, EAP-types: %v", r.BSSID, info.EAPtypes)
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf(fmt.Sprintf("Can't walk directory %q: %v\n", rootPath, err))
	}

	// Analize and enrich
	db.Organize()

	//generate output
	netsFile, err := os.Create("./ESS.csv")
	apsFile, err := os.Create("./BSS.csv")
	rawFile, err := os.Create("./RAW.csv")
	defer netsFile.Close()
	defer apsFile.Close()
	defer rawFile.Close()
	log.Infof("Unique ESS found: %v", len(db.GetESSIDs()))
	log.Infof("Unique BSS found: %v", len(db.GetBSSIDs()))
	outBSS(db, apsFile)
	outESS(db, netsFile)
	outRaw(db, rawFile)

	// Output other ap setups, hidden ess

	//	for _,setup := range ap.setups {
	//		var descriptions []string
	//		// Generate description
	//		if setup.essid == "" {
	//			descriptions = append(descriptions,"hidden")
	//		}
	//
	//
	//		hiddenstr := ""
	//		if setup.hidden {
	//			hiddenstr = "hidden"
	//		}
	//		// Generate encryption list
	//		encstring := ""
	//		for e := range  {
	//			encstring = strings.Join(setup.encryptions,"/")
	//		}
	//		uptime := parsedTime(setup.uptime)
	//
	//	}
	//}
}
