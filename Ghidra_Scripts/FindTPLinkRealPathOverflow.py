# Execute HeadLeaese ./analyzeHeadless project_folder project_name -import "/Users/hdbreaker/Desktop/Routers_Research/http_wr1043" -postscript ~/ghidra_scripts/FindTPLinkOverflows.py
import os
import json
import uuid
from graphviz import Graph
from ghidra.program.model.address import Address
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *

binary_name = ""
argvs = getScriptArgs()
if argvs[0] != "":
  binary_name = argvs[0]

ghidra_default_dir = os.getcwd()

sinks = [                    
    "realpath"
    ]

sink_dic = {}
parent_func_dic = []
duplicate = []
listing = currentProgram.getListing()
ins_list = listing.getInstructions(1)
func = getFirstFunction()

while func is not None:
    func_name = func.getName()
    
    #check if function name is in sinks list
    if func_name in sinks and func_name not in duplicate:
        duplicate.append(func_name)
        entry_point = func.getEntryPoint()
          # Get XREF from IAT EntryPoint
        references = getReferencesTo(entry_point)
    
        #iterate through all cross references to potential sink
        for ref in references:
          call_addr = ref.getFromAddress()
          print "Function Called at Address: %s" % call_addr # Print vuln Function Call Address
                
          #Get Parent function Name
          parent_func_name = getFunctionBefore(call_addr)
          print "Parent Function: %s" % parent_func_name
          
          if parent_func_name != None:
            if sink_dic.get(parent_func_name, None) is not None:
              if sink_dic[parent_func_name].get(func_name,None) is not None:
                if call_addr not in sink_dic[parent_func_name][func_name]['call_address']:
                  sink_dic[parent_func_name][func_name]['call_address'].append(call_addr)
              else:
                sink_dic[parent_func_name] = {func_name:{"address":entry_point,"call_address":[call_addr]}}
            else:
              str = "{\"%s\":{\"%s\":{\"address\":\"%s\",\"call_address\":[\"%s\"]}}}" % (parent_func_name, func_name, entry_point, call_addr)
              print str
              json_obj = json.loads(str)
              sink_dic.update(json_obj)
  
    #set the function to the next function
    func = getFunctionAfter(func)

graph = Graph("ReferenceTree")
graph.graph_attr['rankdir'] = 'LR'

duplicate = 0

for parent_func_name,sink_func_list in sink_dic.items():
  graph.node(parent_func_name,parent_func_name,style="filled",color="blue",fontcolor="white")
  for sink_name,sink_list in sink_func_list.items():
    graph.node(sink_name,sink_name,style="filled",color="red",fontcolor="white")
    for call_addr in sink_list['call_address']:
      if duplicate != call_addr:
        graph.edge(parent_func_name,sink_name,label=call_addr)
        duplicate = call_addr

if binary_name != "":
  file_output = os.path.join(ghidra_default_dir+"/Analysis_Results/",binary_name+".gv")
else:
  file_output = os.path.join(ghidra_default_dir+"/Analysis_Results/",uuid.uuid4().urn[9:]+".gv")
try:
    graph.render(file_output,view=True)
except:
  clean_cmd = "rm %s" % file_output
  os.system(clean_cmd)
  print ""
  print "##################### DONE #####################"
  print "You can find the file in: %s.pdf" % file_output
  print "################################################"
  print ""
