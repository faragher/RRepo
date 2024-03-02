###
#
# RRepo - Reticulum Firmware Repo
#
# Alpha testing version. 
###

import RNS
import os
from LXMF import LXMessage
import LXMF
import RNS.vendor.umsgpack as msgpack
import json
import time
import hashlib

Firmwares = {}
Boards = {}
Versions = {}
Latest = {}


# Main class
class Repository:

  def __init__(self,path=None):
  
    self.ServerName = "Testbed Firmware Server"
    global Firmwares
    
    self.link = None
    self.server_lxmf_delivery = None
    self.lxm_router = None
    if path:
      RNS.log("Loading repo from "+str(path))
      self.apppath = path
      
    else:
      self.apppath = os.path.expanduser("~")+"/.RRepo"
      RNS.log("Path is None, defaulting to "+ self.appath)
    
      
    self.repopath = os.path.join(self.apppath,"firmware")
    identitypath = self.apppath+"/storage/identity"
    os.makedirs(self.apppath+"/firmware/Latest",exist_ok=True) # Fails gracefully
    os.makedirs(self.apppath+"/storage",exist_ok=True) # Fails gracefully
    if os.path.exists(identitypath):
      self.server_identity = RNS.Identity.from_file(identitypath)
      print("Loading identity")
    else:
      print("Making new identity")
      self.server_identity = RNS.Identity()
      self.server_identity.to_file(identitypath)
    
    reticulum = RNS.Reticulum()
    
    self.server_destination = RNS.Destination(
      self.server_identity,
      RNS.Destination.IN,
      RNS.Destination.SINGLE,
      "RRepo",
      "firmware"
    )
    
    self.server_destination.register_request_handler("RETR",response_generator = self.FirmwareDownloadCallback,allow = RNS.Destination.ALLOW_ALL)
    self.server_destination.register_request_handler("BOARD",response_generator = self.ListBoards,allow = RNS.Destination.ALLOW_ALL)
    self.server_destination.register_request_handler("VERSION",response_generator = self.ListVersions,allow = RNS.Destination.ALLOW_ALL)
    self.server_destination.register_request_handler("LATEST",response_generator = self.ListLatest,allow = RNS.Destination.ALLOW_ALL)
    self.server_destination.set_link_established_callback(self.ClientLinkEstablished)
    
    self.LoadAllFromStorage()
    RNS.log("Available firmwares:")
    for F in Firmwares:
      RNS.log("  "+F)
    self.announceLoop(self.server_destination)
    
  def ClientLinkEstablished(self,link):
    link.set_link_closed_callback(self.ClientLinkClosed)
    
  def ClientLinkClosed(self,link):
    RNS.log("Client Disconnected")
    
  def announceLoop(self, destination):
    # Let the user know that everything is ready
    RNS.log("RRepo server "+RNS.prettyhexrep(destination.hash)+" running")
    RNS.log("(Ctrl-C to quit)")
    last_action_time = None;
    last_announce_time = None;
    ANNOUNCE_RATE = 3000
    while True:
      current_time = time.time()
      # Check if we should announce
      if last_announce_time:
        if current_time > (last_announce_time+ANNOUNCE_RATE):
          last_announce_time = current_time
          destination.announce(app_data=self.ServerName.encode("utf-8"))
          RNS.log("Sent announce from "+RNS.prettyhexrep(destination.hash))
      else: # No last announce, so we should announce now.
        destination.announce(app_data=self.ServerName.encode("utf-8"))
        last_announce_time = current_time
        RNS.log("Sent announce from "+RNS.prettyhexrep(destination.hash))
      #Timeout/announce error <= 4 sec. Tradeoff for reducing cycles
      time.sleep(5) 

  def Index(self, version = None, board = None):
    global Boards, Versions, Latest
    if version:
      if not version or not version in Versions:
        print("Version "+str(version)+" is not available")
        return
      #print("Version "+str(version))
      for b in Versions[version]:
        print(Versions[version][b].board)
    elif board:
      if not board in Boards:
        print("Board "+str(board)+" is not available")
        return
      #print("Board "+str(board))
      for v in Boards[board]:
        print(Boards[board][v].version)
    else:
      for l in Latest:
        print(Latest[l].board+" V"+Latest[l].version)
        
  def ListBoards(path,command,data,link_id,remote_identity,requested_at):
    global Boards, Versions, Latest
    payload = []
    for v in Boards[data]:
      payload.append(Boards[data][v].version)
    return msgpack.packb(payload)
  
  def ListVersions(path,command,data,link_id,remote_identity,requested_at):
    global Boards, Versions, Latest
    payload = []
    for b in Versions[data]:
      payload.append(Versions[data][b].board)
    return msgpack.packb(payload)
  
  def ListLatest(path,command,data,link_id,remote_identity,requested_at):
    global Boards, Versions, Latest
    payload = []
    print(Latest)
    for l in Latest:
      payload.append(l)
    return msgpack.packb(payload)
        
  def client_disconnected(link):
    RNS.log("Client disconnected")
      
  def LoadAllFromStorage(self):
    global Boards, Versions, Latest
    for VPath in os.listdir(self.repopath):
      handle = os.path.join(self.repopath,VPath)
      Versions[VPath] = {}
      if os.path.isdir(handle):
        try:
          releasejson = None
          version_dir = os.path.join(self.repopath,VPath)
          if os.path.exists(version_dir+"/release.json"):
            with open(version_dir+"/release.json") as f:
              releasejson = json.load(f)
          for FirmwareFile in os.listdir(version_dir):
            #print(FirmwareFile)
            extension = FirmwareFile.split(".")[-1]
            if extension == "zip":
              nfo = FirmwareFile+".nfo"
              jsonmeta = FirmwareFile+".json"
              if os.path.exists(os.path.join(version_dir,nfo)):
                #print(".nfo exists")
                M = self.LoadMetadata(os.path.join(version_dir,nfo))
                self.ReadyFirmware(M,os.path.join(version_dir,FirmwareFile))
                if VPath == "Latest":
                  self.ReadyLatestFirmware(M,os.path.join(version_dir,FirmwareFile))
              elif os.path.exists(os.path.join(version_dir,jsonmeta)):
                M = self.LoadMetadataJSON(os.path.join(version_dir,jsonmeta))
                self.ReadyFirmware(M,os.path.join(version_dir,FirmwareFile))
                if VPath == "Latest":
                  self.ReadyLatestFirmware(M,os.path.join(version_dir,FirmwareFile))
              elif releasejson:
                if FirmwareFile in releasejson:
                  RNS.log(FirmwareFile+" has no metadata. Falling back to release.json",RNS.LOG_DEBUG)
                  self.ReadyFirmwareJSON(FirmwareFile,releasejson[FirmwareFile]['version'],releasejson[FirmwareFile]['hash'],os.path.join(version_dir,FirmwareFile))
                  if VPath == "Latest":
                    self.ReadyLatestFirmwareJSON(FirmwareFile,releasejson[FirmwareFile]['version'],releasejson[FirmwareFile]['hash'],os.path.join(version_dir,FirmwareFile))
                else:
                  RNS.log(FirmwareFile+" has no metadata and is not in release.json!",RNS.LOG_ERROR)
              #else:
                #print("No release.json found")
            
        except Exception as e:
          RNS.log("Error loading repository: "+str(e),RNS.LOG_ERROR)
    
  def LoadMetadata(self, path):
    try:
      with open(path,"br") as f:
        m = f.read()
      I = FirmwareMetadata(None, None, None)
      I.unpack(m)
      return I
    except Exception as e:
      RNS.log("Error reading metadata from "+path,RNS.LOG_ERROR)
      RNS.log(e,RNS.LOG_ERROR)
      
  def LoadMetadataJSON(self, path):
    try:
      I = FirmwareMetadata(None, None, None)
      I.fromJSON(path)
      return I
    except Exception as e:
      RNS.log("Error reading metadata from "+path,RNS.LOG_ERROR)
      RNS.log(e,RNS.LOG_ERROR)
      
  def ReadyFirmware(self, Meta, path):
    global Boards, Versions, Latest
    FWC = FirmwareContainer(Meta,path)
    RequestPath = Meta.version+"/"+Meta.board
    RNS.log("Loaded "+FWC.metadata.board+" V"+FWC.metadata.version+" hash: "+FWC.metadata.hash,RNS.LOG_INFO)
    Firmwares[RequestPath]=FWC
    RNS.log("Created resouce at "+RequestPath,RNS.LOG_INFO)
    if not Meta.version in Versions:
      Versions[Meta.version] = {}
    Versions[Meta.version][Meta.board] = Meta
    if not Meta.board in Boards:
      Boards[Meta.board] = {}
    Boards[Meta.board][Meta.version] = Meta
    #print("Firmware ready")
    
  def ReadyFirmwareJSON(self, name, version, hash, path):
    FWM = FirmwareMetadata(name,version,hash)
    self.ReadyFirmware(FWM, path)
    
  def ReadyLatestFirmware(self, Meta, path):
    global Boards, Versions, Latest
    RNS.log(Meta.board+" V"+Meta.version+" set as Latest.",RNS.LOG_INFO)
    Latest[Meta.board] = Meta
    
  def ReadyLatestFirmwareJSON(self, name, version, hash, path):
    global Boards, Versions, Latest
    FWM = FirmwareMetadata(name,version,hash)
    RNS.log(FWM.board+" V"+FWM.version+" set as Latest.",RNS.LOG_INFO)
    Latest[FWM.board] = FWM
 
    
  def FirmwareDownloadCallback(path,command,data,link_id,remote_identity,requested_at):
    global Firmwares
    if not data or data not in Firmwares:
      RNS.log("Firmware "+data+" not found")
      return FirmwarePackage(None,None,False).pack()
    #return "Beep".encode("utf-8")
    else:
      FWC = Firmwares[data]
      hash = FWC.metadata.hash
      RNS.log("Loading firmware from "+str(Firmwares[data].repopath),RNS.LOG_INFO)
      with open(Firmwares[data].repopath,"rb") as f:
        FW = f.read()
      return FirmwarePackage(FW,hash,True).pack()
      
  
  
class FirmwarePackage:
  def __init__(self, FW, hash, valid):
    self.FW = FW
    self.hash = hash
    self.valid = valid
    
  def pack(self):
    payload = {}
    payload["firmware"] = self.FW
    payload["valid"] = self.valid
    payload["hash"] = self.hash
    buffer=msgpack.packb(payload)
    return buffer
    
  def unpack(self, packed):
    try:
      payload = msgpack.unpackb(packed)
      self.FW = payload["firmware"]
      self.valid = True
      self.hash = payload["hash"]
    except Exception as e:
      RNS.log("Failed to unpack firmware container. Bad contents? Exception: "+e)
  

class FirmwareContainer:
  def __init__(self, meta, path):
    self.metadata = meta
    self.repopath = path
    

class FirmwareMetadata:
  def __init__(self, board, version, hash):
    self.board = board
    self.version = version
    self.hash = hash
    
  def fromJSON(self,path):
    with open(path,"r") as f:
      J = json.load(f)
    self.board = J["board"]
    self.version = J["version"]
    self.hash = J["hash"]
    
    
  def pack(self):
    payload = {}
    payload["board"] = self.board
    payload["version"] = self.version
    payload["hash"] = self.hash
    buffer=msgpack.packb(payload)
    return buffer
    
  def unpack(self,packed):
    try:
      payload = msgpack.unpackb(packed)
      self.board = payload["board"]
      self.version = payload["version"]
      self.hash = payload["hash"]
    except Exception as e:
      RNS.log("Failed to unpack file. Bad contents? Exception: "+e)
    

class FirmwareDownloader:
  def __init__(self,server_hash):
    self.link_established = False
    if isinstance(server_hash, str):
      self.server_hash = bytes.fromhex(server_hash)
    else:
      self.server_hash = server_hash
    
  def Connect(self):
    if not RNS.Transport.has_path(self.server_hash):
      RNS.log("Destination is not yet known. Requesting path and waiting for announce to arrive...")
      RNS.Transport.request_path(self.server_hash)
      while not RNS.Transport.has_path(self.server_hash):
        time.sleep(0.1)
    self.server_identity = RNS.Identity.recall(self.server_hash)
    self.server_destination = RNS.Destination(self.server_identity,RNS.Destination.OUT, RNS.Destination.SINGLE,"RRepo","firmware")
    self.link = RNS.Link(self.server_destination)
    self.link.set_link_established_callback(self.LinkEstablished)
    self.link.set_link_closed_callback(self.LinkClosed)
      
  def LinkEstablished(self, link):
    self.link_established = True
    print("Link established")

    
  def RequestFailed(self,receipt):
    RNS.log("Request failed.")
   
  def LinkClosed(self, link):
    self.link_established = False
    if link.teardown_reason == RNS.Link.TIMEOUT:
      RNS.log("The link timed out")
    elif link.teardown_reason == RNS.Link.DESTINATION_CLOSED:
      RNS.log("The link was closed by the server")
    else:
      RNS.log("Link closed") 
    RNS.Reticulum.exit_handler()
    
  def RequestFirmware(self,FW_name):
    timeout = 0
    while not self.link_established and timeout < 600:
      timeout += 1
      time.sleep(.1)
    
    if self.link_established: 
      req = self.link.request("RETR" , FW_name, self.ResponseReceived, self.RequestFailed)
    else:
      RNS.log("Link not established",RNS.LOG_ERROR)
      return
    
    RNS.log("Waiting for request status != SENT, currently "+str(req.status), RNS.LOG_DEBUG)
    timeout = 0
    while (req.status == 0x01 or req.status == 0x03) and timeout < 600:
      timeout += 1
      time.sleep(.1)
     
    RNS.log("Request status = "+str(req.status),RNS.LOG_DEBUG)
    if req.status == 0x00:
      RNS.log("Request failed.",RNS.LOG_ERROR)
      return
    RNS.log("Firmware retrieved", RNS.LOG_INFO)
    FW = FirmwarePackage(None,None,None)
    FW.unpack(req.response)
    #RNS.log("hash is: "+str(FW.hash), RNS.LOG_INFO)
    return FW
    
  def VerifyFirmware(self,FW):
    expected_hash = FW.hash
    file_hash = hashlib.sha256(FW.FW).hexdigest()
    RNS.log("Expected hash:   "+str(expected_hash),RNS.LOG_DEBUG)
    RNS.log("Calculated hash: "+str(file_hash),RNS.LOG_DEBUG)
    return expected_hash == file_hash
    
  def Close(self):
    if self.link:
      self.link.teardown()
    RNS.log("Terminating link")    
    
  def ListBoards(self,target):
    timeout = 0
    while not self.link_established and timeout < 600:
      timeout += 1
      time.sleep(.1)
    
    if self.link_established: 
      req = self.link.request("BOARD" , target, self.ResponseReceived, self.RequestFailed)
    else:
      RNS.log("Link not established",RNS.LOG_ERROR)
      return
    
    RNS.log("Waiting for request status != SENT, currently "+str(req.status), RNS.LOG_DEBUG)
    timeout = 0
    while (req.status == 0x01 or req.status == 0x03) and timeout < 600:
      timeout += 1
      time.sleep(.1)
     
    RNS.log("Request status = "+str(req.status),RNS.LOG_DEBUG)
    if req.status == 0x00:
      RNS.log("Request failed.",RNS.LOG_ERROR)
      return
    RNS.log("Firmware retrieved", RNS.LOG_INFO)
    Response = msgpack.unpackb(req.response)
    
    #RNS.log("hash is: "+str(FW.hash), RNS.LOG_INFO)
    return Response
    
  def ListVersions(self,target):
    timeout = 0
    while not self.link_established and timeout < 600:
      timeout += 1
      time.sleep(.1)
    
    if self.link_established: 
      req = self.link.request("VERSION" , target, self.ResponseReceived, self.RequestFailed)
    else:
      RNS.log("Link not established",RNS.LOG_ERROR)
      return
    
    RNS.log("Waiting for request status != SENT, currently "+str(req.status), RNS.LOG_DEBUG)
    timeout = 0
    while (req.status == 0x01 or req.status == 0x03) and timeout < 600:
      timeout += 1
      time.sleep(.1)
     
    RNS.log("Request status = "+str(req.status),RNS.LOG_DEBUG)
    if req.status == 0x00:
      RNS.log("Request failed.",RNS.LOG_ERROR)
      return
    RNS.log("Firmware retrieved", RNS.LOG_INFO)
    Response = msgpack.unpackb(req.response)
    
    #RNS.log("hash is: "+str(FW.hash), RNS.LOG_INFO)
    return Response
    
  def ListLatest(self):
    timeout = 0
    while not self.link_established and timeout < 600:
      timeout += 1
      time.sleep(.1)
    
    if self.link_established: 
      req = self.link.request("LATEST" , None , self.ResponseReceived, self.RequestFailed)
    else:
      RNS.log("Link not established",RNS.LOG_ERROR)
      return
    
    RNS.log("Waiting for request status != SENT, currently "+str(req.status), RNS.LOG_DEBUG)
    timeout = 0
    while (req.status == 0x01 or req.status == 0x03) and timeout < 600:
      timeout += 1
      time.sleep(.1)
     
    RNS.log("Request status = "+str(req.status),RNS.LOG_DEBUG)
    if req.status == 0x00:
      RNS.log("Request failed.",RNS.LOG_ERROR)
      return
    RNS.log("Firmware retrieved", RNS.LOG_INFO)
    Response = msgpack.unpackb(req.response)
    
    #RNS.log("hash is: "+str(FW.hash), RNS.LOG_INFO)
    return Response
    
 
  
  def ResponseReceived(self,receipt):
    FWC = msgpack.unpackb(receipt.response)
  
