import time
import RNS
import RNS.vendor.umsgpack as msgpack
import RRepo

# BTB Node Romeo Repository - Feel free to use
destination_hexhash = "29fafc22f352028644a35355a2f80c59"
destination_hash = bytes.fromhex(destination_hexhash)

reticulum = RNS.Reticulum()
identity = RNS.Identity()
 
D = RRepo.FirmwareDownloader(destination_hexhash)
D.Connect()
print(D.ListBoards("lora32v21"))
print(D.ListVersions("1.70"))
print(D.ListLatest())

FW = D.RequestFirmware("1.70/lora32v21")
if FW.valid:
  Firmware = FW.FW
  if D.VerifyFirmware(FW):
    RNS.log("Firmware downloaded and hash matches.")
    RNS.log("At this point you can save FW.FW to file or use it from memory. Download complete")
  else: 
    RNS.log("Invalid hash. Rejecting",RNS.LOG_ERROR)
else: 
  RNS.log("Invalid return.",RNS.LOG_ERROR)
time.sleep(10)
D.Close()

