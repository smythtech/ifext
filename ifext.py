#!/usr/bin/python3

import requests
import argparse
import signal
import sys
import json
from getpass import getpass

verbose = 0

def handle_args():
  parser = argparse.ArgumentParser(prog="ifext.py", description="SDN host InterFace EXTension (IFEXT) Kit. Creates and installs flow rules that allow an SDN switch to act as an extension to a single physical network interface.", epilog="Author: Dylan Smyth (https://github.com/smythtech)")
  parser.add_argument("-l", "--load-config", help="Config file with port mappings.", required=False)
  parser.add_argument("-u", "--user", help="Username for REST API. You will be prompted for the password.", required=False)
  parser.add_argument("-v", "--verbose", help="Show additional output.", required=False, action='store_true')
  parser.add_argument('--version', action='version', version='%(prog)s 1.0')

  if(len(sys.argv) < 2):
    parser.print_help()
    exit(0)

  return parser.parse_args()

def sig_handler(sig, frame):
  print("[+] Exiting.")
  exit()

def check_config(config):
  ok = ("controller" in config and "controller-url" in config and "source-port" in config and "port-mappings" in config)
  if("controller-url" in config and config["controller-url"][-1] == "/"):
    config["controller-url"] = config["controller-url"][:-1]
  return ok

def test_controller(config):
  url = config["controller-url"]
  try:
    url += get_controller_endpoint(config, "devices")
    test = config["session"].get(url)
    if(test.status_code != 200):
      print(f"[!] Could not contact REST endpoint {url}")
      print(test.status_code)
      if(test.status_code == 401):
        print("[!] Got 401 unauthorized. Please proivide valid credientias using the '-u' option.")
      exit(1)
  except Exception as e:
    print("[!] Could not connect to controller. Is the IP/Hostname and port correct?")
    print(e)
    exit(1)

def get_switch_data(config):
  url = config["controller-url"] + get_controller_endpoint(config, "devices")
  switch_data = config["session"].get(url).json()
  dpid = ""
  if(len(switch_data["devices"]) > 1):
    print("[+] Over 1 switch detected. Please indicate the switch you wish to use.")
    for i in range(0, len(switch_data["devices"])):
      print(f"{i+1}. {switch_data['devices'][i]['id']}\t{switch_data['devices'][i]['mfr']}\t{switch_data['devices'][i]['hw']}")
    try:
      selected = int(input("Enter the number of the dpid you wish to use: ")) - 1
      dpid = switch_data["devices"][selected]["id"]
    except:
      print("[!] Error selected switch unavailable")
      exit(1)
  elif(len(switch_data["devices"]) == 0):
    print("[!] No switches found!")
    exit(1)
  else:
    print("[+] Found 1 switch. Using this.")
    dpid = switch_data["devices"][0]["id"]

  return dpid

def validate_switch_ports(config):
  url = config["controller-url"] + get_controller_endpoint(config, "devices") + "/" + config["dpid"] + "/ports"
  data = config["session"].get(url).json()
  num_ports = len(data["ports"])
  if((num_ports < len(config["port-mappings"])+1) or (num_ports < config["source-port"])):
    print("[!] Invalid port configuration detected. Please check that the port mapping falls within the number of ports available on the switch.")
    exit(1)
  elif(config["source-port"] in config["port-mappings"].values()):
    print("[!] Source port cannot be mapped to a host.")
    exit(1)

  print("\tPort check ok.")

def generate_forwarding_rules_onos(config):
  flows = []

  # Flow rules for additional traffic management (broadcasts, LLDP, BDDP, etc.)


  # Prevent LLDP forwarding to controller from network
  onos_flow = {}
  onos_flow["priority"] = 40001
  onos_flow["timeout"] = 0
  onos_flow["isPermanent"]  = "true"
  onos_flow["deviceId"] = config["dpid"]
  onos_flow["treatment"] = {}
  onos_flow["selector"] = {"criteria": []}
  onos_flow["selector"]["criteria"].append({"type": "ETH_TYPE", "ethType": "0x88cc"})
  onos_flow["selector"]["criteria"].append({"type": "IN_PORT", "port": "controller"})
  flows.append(onos_flow)


  # Output LLDP to first port only.
  onos_flow = {}
  onos_flow["priority"] = 40001
  onos_flow["timeout"] = 0
  onos_flow["isPermanent"]  = "true"
  onos_flow["deviceId"] = config["dpid"]
  onos_flow["treatment"] = {"instructions": []}
  onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["source-port"]})
  onos_flow["selector"] = {"criteria": []}
  onos_flow["selector"]["criteria"].append({"type": "ETH_TYPE", "ethType": "0x88cc"})
  flows.append(onos_flow)

  # Output broadcasts to source port only.
  onos_flow = {}
  onos_flow["priority"] = 40001
  onos_flow["timeout"] = 0
  onos_flow["isPermanent"]  = "true"
  onos_flow["deviceId"] = config["dpid"]
  onos_flow["treatment"] = {"instructions": []}
  onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["source-port"]})
  onos_flow["selector"] = {"criteria": []}
  onos_flow["selector"]["criteria"].append({"type": "ETH_DST", "mac": "FF:FF:FF:FF:FF:FF"})
  flows.append(onos_flow)

  '''
  #Prevent ARP from being sent to the controller
  onos_flow = {}
  onos_flow["priority"] = 40000
  onos_flow["timeout"] = 0
  onos_flow["isPermanent"]  = "true"
  onos_flow["deviceId"] = config["dpid"]
  onos_flow["treatment"] = {"instructions": []}
  onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["source-port"]})
  onos_flow["selector"] = {"criteria": []}
  onos_flow["selector"]["criteria"].append({"type": "ETH_TYPE", "ethType": "0x0806"})
  flows.append(onos_flow)


  #Prevent IPv4 from being sent to the controller
  onos_flow = {}
  onos_flow["priority"] = 40000
  onos_flow["timeout"] = 0
  onos_flow["isPermanent"]  = "true"
  onos_flow["deviceId"] = config["dpid"]
  onos_flow["treatment"] = {"instructions": []}
  onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["source-port"]})
  onos_flow["selector"] = {"criteria": []}
  onos_flow["selector"]["criteria"].append({"type": "ETH_TYPE", "ethType": "0x0800"})
  flows.append(onos_flow)
  '''

  # Output broadcast traffic through first port only.
  onos_flow = {}
  onos_flow["priority"] = 40001
  onos_flow["timeout"] = 0
  onos_flow["isPermanent"]  = "true"
  onos_flow["deviceId"] = config["dpid"]
  onos_flow["treatment"] = {"instructions": []}
  onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["source-port"]})
  onos_flow["selector"] = {"criteria": []}
  onos_flow["selector"]["criteria"].append({"type": "ETH_DST", "mac": "FF:FF:FF:FF:FF:FF"})
  flows.append(onos_flow)


  # Forwarding rules to enable Interface Externsion
  for host_mac in config["port-mappings"]:
    onos_flow = {}
    onos_flow["priority"] = 40001
    onos_flow["timeout"] = 0
    onos_flow["isPermanent"]  = "true"
    onos_flow["deviceId"] = config["dpid"]
    onos_flow["treatment"] = {"instructions": []}
    onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["port-mappings"][host_mac]})
    onos_flow["selector"] = {"criteria": []}
    onos_flow["selector"]["criteria"].append({"type": "IN_PORT", "port": config["source-port"]})
    onos_flow["selector"]["criteria"].append({"type": "ETH_SRC", "mac": host_mac})
    flows.append(onos_flow)

    onos_flow = {}
    onos_flow["priority"] = 40001
    onos_flow["timeout"] = 0
    onos_flow["isPermanent"]  = "true"
    onos_flow["deviceId"] = config["dpid"]
    onos_flow["treatment"] = {"instructions": []}
    onos_flow["treatment"]["instructions"].append({"type": "OUTPUT", "port": config["source-port"]})
    onos_flow["selector"] = {"criteria": []}
    onos_flow["selector"]["criteria"].append({"type": "IN_PORT", "port": config["port-mappings"][host_mac]})
    onos_flow["selector"]["criteria"].append({"type": "ETH_DST", "mac": host_mac})
    flows.append(onos_flow)


  flows = {"flows": flows}

  return flows

def disable_lldp(config):
  url = config["controller-url"]
  url += "/onos/v1/network/configuration"

  headers = {"Content-Type": "application/json", "Accept": "application/json"}

  ports = config["port-mappings"].values()
  data = {"ports": {}}

  for port in ports:
    data["ports"][config["dpid"] + "/" + str(port)] =  {"linkDiscovery":{"enabled":False}}

  config["session"].post(url, headers=headers, json=data)


def install_rules(config, flows):
  endpoint_url = config["controller-url"]
  endpoint_url += get_controller_endpoint(config, "flow-install")
  endpoint_url += "?appId=1"

  headers = {"Content-Type": "application/json", "Accept": "application/json"}

  resp = config["session"].post(endpoint_url, headers = headers, json=flows)

def get_rule_generator(config):
  try:
    func = {
  	  "onos": generate_forwarding_rules_onos
          }[config["controller"]]
    return func
  except KeyError:
    print(f"[!] Error. No rule generator for controller {config['controller']}")
    exit(1)

def get_controller_endpoint(config, ep):
  endpoint = {
             "devices":"/devices",
             "flow-install": "/flows"
             }[ep]

  return "/onos/v1" + endpoint

def main():
  global verbose
  args = handle_args()

  if(args.verbose):
    verbose = 1
    print("[*] Verbose output enabled")

  signal.signal(signal.SIGINT, sig_handler)

  if(args.load_config):
    try:
      config = {}
      with open(args.load_config) as f:
        config = json.loads(f.read())
    except Exception as e:
      print("[!] Error reading config file")
      print(e)
      exit(1)

    requests_session = requests.Session()

    if(args.user):
      config["user"] = args.user
      config["password"] = getpass("Password for user " + config["user"] + ": ")
      requests_session.auth = (config["user"], config["password"])

    config["session"] = requests_session

    if(check_config(config)):
      print("[+] Testing connection to controller URL")
      test_controller(config)

      print("[+] Getting switch data from controller")
      config["dpid"] = get_switch_data(config)

      print("[+] Validating switch ports against config")
      validate_switch_ports(config)
      rule_generator = get_rule_generator(config)

      print("[+] Generating flow rules for " + config["controller"])
      rules = rule_generator(config)

      print("[+] Disabling LLDP on ports mapped to hosts")
      disable_lldp(config)

      print(f"[+] Installing flow rules to switch {config['dpid']}")
      install_rules(config, rules)


      print("[+] Controller configuration complete")

    else:
      print("[!] Provided configuration is missing required items. Check example.conf.")
      exit(1)


if __name__ == '__main__':
  main()
