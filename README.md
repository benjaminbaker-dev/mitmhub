mitmhub: Libraries and functionality to automatically perform Man-In-The-Middle (mitm) attacks in python


FRONTEND:
* implement logic to actually get data
* add indicator to whether mitm is running or not
* editor window for configuration 

BACKEND
* install script
* RPC (zerorpc)
features:
  * JSON representation for Network and NetworkNode
  * PCAP
  * Subprocesses instead of threads
  
request_rules_list_json = {
  "node_id":"mac_of_node"
} 
rules_list_response_json = {
   "node_id":"mac_of_node",
   "response":{
      "success": "true"
      "func_name1": ["param_a", "param_b"],
      "func_name2": ["param_a", "param_b"],
    }
}
add_rules_request_json = {
   "node_id":"mac_of_node",
   "request":{
      "func_name1":["filled_param_a", "filled_param_b"]
   }
}
add_rules_response_json = {
   "node_id":"mac_of_node",
   "response":{
       "success":"true"
    }
}
