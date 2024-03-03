The library is incredibly rough, but I expect the actual interface to be generally mature. This system is meant to focus on one thing, buf if additional functionality is actually required, please request it.

The example is straightforward, but general specifications follow:

Client Initialization:

`Initialize Reticulum and create an identity as per normal.`

`Downloader = RRepo.FirmwareDownloader(destination_hexhash) # bytes or string acceptable`

`Downloader.Connect() # Initializes link with repositorty`

Commands
* `list<strings> ListBoards(Board_of_Interest) # Return versions available for board`
* `list<strings> ListVersions(Version_of_Interest)) # Return boards available for version`
* `list<strings> ListLatest()) # Return all board firmware marked "latest"`
* `FirmwareContainer Downloader.RequestFirmware(Path_to_Firmware) # Path is string made up of version/firmware. Example: 1.70/rnode_firmware_lora32v21.zip`
* `bool VerifyFirmware(FirmwareContainer) # Verifies packaged firmware and hash, returns True if matching`

Object
FirmwareContainer: Dictionary
* `bytes FW: Firmware binary`
* `string hash: Expected hash from repository`
* `bool valid: True under normal operation. Server marks false if request rejected`

Server Repository
Designed for the file structure ./version/firmwarefile.zip however with the exception of the ./Latest/ directory, metadata overrides the path.
The program supports two classes of metadata in three formats. The primary format is a dictionary with the following fields, all strings:
* `board`
* `version`
* `hash`

The primary format is an .nfo file, (foo.zip -> foo.zip.nfo) which is simply that dictionary packed by msgpack. It is designed for machine to machine convenience, but may be depreciated if not advantageous.

If no .nfo file exists, it looks for a json file (foo.zip -> foo.zip.json) with the same data.

As a fallback, it can check a standard release.json file, but this should be considered legacy behavior.


