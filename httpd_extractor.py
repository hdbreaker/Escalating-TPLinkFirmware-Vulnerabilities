import os
import time

class HTTPDExtractor:

	def __init__(self):
			self.firmwares = os.listdir("Firmwares")
			self.current_path = os.getcwd()
			
	def extract_httpd(self):
		self.cleaner()
		for firmware in self.firmwares:
			self.copy_firmware_to_tmp(firmware)
			self.binwalk_firmware(firmware)
			self.copy_httpd_binary(firmware)
		self.done()

	def cleaner(self):
		cleaner_cmd = "rm %s/HTTPD_Binaries/*" % self.current_path
		os.system(cleaner_cmd)

	def copy_firmware_to_tmp(self, firmware):
		copy_cmd = "cp Firmwares/%s /tmp/" % firmware
		os.system(copy_cmd)
		time.sleep(1)

	def binwalk_firmware(self, firmware):
		binwalk_cmd = "docker run --rm -v /tmp/:/tmp/ gillis57/binwalk -e /tmp/%s" % firmware
		os.system(binwalk_cmd)
		time.sleep(1)
	
	def copy_httpd_binary(self, firmware):
		copy_cmd = "cp /tmp/_%s.extracted/squashfs-root/usr/bin/httpd %s/HTTPD_Binaries/httpd_%s" % (firmware, self.current_path, firmware)
		copy_cmd2 = "cp /tmp/_%s.extracted/squashfs-root/usr/sbin/httpd %s/HTTPD_Binaries/httpd_%s" % (firmware, self.current_path, firmware)
		cmd = "%s || %s" % (copy_cmd , copy_cmd2)
		os.system(cmd)
		time.sleep(1)

	def done(self):
		print("###########################################")
		print("#                  DONE                   #")
		print("###########################################")
		print("You will find the httpd binaries in: \"%s/HTTPD_Binaries\" folder") % self.current_path

extractor = HTTPDExtractor()
extractor.extract_httpd()