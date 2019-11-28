import os
import time
# ./analyzeHeadless ./test4 test4 -import "/Users/hdbreaker/Desktop/Routers_Research/httpd_archerC50" -postscript ~/ghidra_scripts/FindTPLinkRealPathOverflows.py {binary_name_arg}

class Analyser():
  def __init__(self):
    self.current_path = os.getcwd()
    self.binaries = os.listdir("HTTPD_Binaries")
    self.ghidra_script_name   = "FindTPLinkRealPathOverflow.py"
    self.ghidra_script_path   = "%s/Ghidra_Scripts/%s" % (self.current_path, self.ghidra_script_name)
    self.ghidra_headless_path = "%s/ghidra_9.0.4/support/analyzeHeadless" % (self.current_path)
      
  def execute_script(self):
    self.cleaner() 
    for binary in self.binaries:
      os.system("mkdir ghidra_tmp_projects/%s" % binary)
      analyse_cmd = "%s ghidra_tmp_projects/%s %s -import \"%s/HTTPD_Binaries/%s\" -postscript %s %s" % (self.ghidra_headless_path, binary, binary, self.current_path, binary, self.ghidra_script_path, binary)
      print(analyse_cmd)
      os.system(analyse_cmd)
      time.sleep(1)
  
  def cleaner(self):
    cleaner_cmd = "rm %s/Analysis_Results/*" % self.current_path
    os.system(cleaner_cmd)
    os.system("rm -rf ghidra_tmp_projects")
    os.system("mkdir ghidra_tmp_projects")

analizer = Analyser()
analizer.execute_script()