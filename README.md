mitmhub: Libraries and functionality to automatically perform Man-In-The-Middle (mitm) attacks in python


FRONTEND:
* add indicator to whether mitm is running or not: change color
* display and remove rules

BACKEND
* display and remove rules
features:
  * PCAP
  * throw exceptions in json functions for frontend display
  * add drop packet rule
  
request_rules_list_json = {
  "node_id":"mac_of_node"
} 

rules_list_response_json = {
   "node_id":"mac_of_node",
   "response":{
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
