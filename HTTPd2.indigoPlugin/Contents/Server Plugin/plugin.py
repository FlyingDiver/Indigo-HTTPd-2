#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import base64
import logging
import json
import ssl
import os.path
import hashlib
import time
import threading
import requests

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import parse_http_list, parse_keqv_list

import indigo

REALM = "HTTPd Plugin"

########################################

class MyHTTPServer(HTTPServer):

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)

        self.httpUser = None
        self.httpPassword = None
        self.digestRequired = None
        self.devID = None
        self.state_list = None
        self.logger = logging.getLogger("Plugin.MyHTTPServer")

    def set_auth_params(self, httpUser, httpPassword, digestRequired):
        self.httpUser = httpUser
        self.httpPassword = httpPassword
        self.digestRequired = bool(digestRequired)
        self.logger.debug(f"MyHTTPServer, username = {self.httpUser}, password = {self.httpPassword}, digest = {self.digestRequired}")
        
    def set_dev_id(self, devID):
        self.devID = devID
        self.logger.debug(f"MyHTTPServer, devID = {self.devID}")
        
    def set_state_list(self, state_list):
        self.state_list = state_list
    
class MyRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.logger = None

    def send_reply(self, code):

        nonce = hashlib.md5(f"{time.time()}:{REALM}".encode()).hexdigest()
        if self.server.digestRequired:
            authHeader = f'Digest realm="{REALM}", nonce="{nonce}", algorithm="MD5", qop="auth"'
        else:
            authHeader = f'Digest realm="{REALM}", nonce="{nonce}", algorithm="MD5", qop="auth" Basic realm="{REALM}"'
            
        self.send_response(code)
        self.send_header('WWW-Authenticate', authHeader)
        self.send_header("Content-type", "text/html")
        self.end_headers()
    
    def is_authorized(self):

        if len(self.server.httpPassword) == 0:    # no authentication needed
            self.logger.debug("MyRequestHandler: No password specified in device configuration, skipping authentication")
            return True

        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            self.logger.debug("MyRequestHandler: Request has no Authorization header")
            return False

        auth_scheme, auth_params  = auth_header.split(" ", 1)
        auth_scheme = auth_scheme.lower()
        
        if auth_scheme == 'basic':
            auth = base64.b64decode(auth_params).decode('utf-8')
            self.logger.debug(f"auth = {auth}")

            username, password = auth.split(":", 1)
            auth_map = {"username": username, "password": password}
            
        elif auth_scheme == 'digest':                       # Convert the auth params to a dict
            items = parse_http_list(auth_params)
            auth_map = parse_keqv_list(items)
            
        else:
            self.logger.debug(f"MyRequestHandler: Invalid authentication scheme: {auth_scheme}")
            return False
                
        self.logger.debug(f"MyRequestHandler: auth_map = {auth_map}")
            
        # check username
        if auth_map["username"] != self.server.httpUser:
            self.logger.debug("MyRequestHandler: Username mismatch")
            return False
                
        if auth_scheme == "basic":
            if self.server.digestRequired:
                self.logger.debug(f"MyRequestHandler: {auth_scheme} Authorization not allowed".capitalize())
                return False
                
            if auth_map["password"] == self.server.httpPassword:
                self.logger.debug(f"MyRequestHandler: {auth_scheme} Authorization valid".capitalize())
                return True
            else:
                self.logger.debug(f"MyRequestHandler: {auth_scheme} Authorization failed".capitalize())
                return False
 
        elif auth_scheme == "digest":
            h1 = hashlib.md5((self.server.httpUser + ":" + REALM + ":" + self.server.httpPassword).encode()).hexdigest()
            h2 = hashlib.md5((self.command + ":" + auth_map["uri"]).encode()).hexdigest()
            rs = (h1 + ":" + auth_map["nonce"] + ":" + auth_map["nc"] + ":" + auth_map["cnonce"] + ":" + auth_map["qop"] + ":" + h2).encode()
            if hashlib.md5(rs).hexdigest() == auth_map["response"]:
                self.logger.debug(f"MyRequestHandler: {auth_scheme} Authorization valid".capitalize())
                return True
            else:
                self.logger.debug(f"MyRequestHandler: {auth_scheme} Authorization failed".capitalize())
                return False

        else:
            self.logger.debug(f"MyRequestHandler: {auth_scheme} Authorization invalid".capitalize())
            return False

    def do_setvar(self, request):                          
        device = indigo.devices[self.server.devID]
        self.logger.debug(f"{device.name}: MyRequestHandler: updating device")

        saved_states = json.loads(device.pluginProps.get("saved_states", "{}"))
        self.logger.threaddebug(f"{device.name}: MyRequestHandler: saved_states = {saved_states}")
        
        new_states = {}               
        state_list = []

        query = parse_qs(request.query)
        for key in query:
            value = query[key][0]
            state_list.append({'key': str(key), 'value': value})
            new_states[key] = value
 
        if device.pluginProps.get("updateTimestamp", False):
            state_list.append({'key': 'http2_timestamp', 'value': time.strftime("%x %X")})
 
        self.logger.threaddebug(f"{device.name}: MyRequestHandler: new_states = {new_states}")

        if saved_states != new_states:
            newProps = device.pluginProps
            newProps["saved_states"] = json.dumps(new_states)
            device.replacePluginPropsOnServer(newProps)

        self.server.set_state_list(state_list)
        device.stateListOrDisplayStateIdChanged()    
        device.updateStatesOnServer(state_list)

    def do_webhook(self, request):      
        self.logger.debug(f"do_webhook query = {request.query}, path = {request.path}")

        broadcastDict = {}
        varsDict = {}
        headers = {}
        reqDict = {}
        
        try:
            query = parse_qs(request.query)
            for key in query:
                varsDict[key] = query[key][0]
            broadcastDict["vars"] = varsDict
        except Exception as e:
            broadcastDict["vars"] = None
        
        try:
            headers = {key:value for (key,value) in self.headers.items()}
            broadcastDict["headers"] = headers
        except Exception as e:
            broadcastDict["headers"] = None

        try:
            client_host, client_port = self.client_address
            reqDict = {"path": request.path, "command": self.command, "client": client_host}
            broadcastDict["request"]  = reqDict
        except Exception as e:
            broadcastDict["request"]  = None

        if self.command == "POST":
            try:
                data = self.rfile.read(int(self.headers['Content-length']))
                broadcastDict["payload"] = data
            except Exception as e:
                broadcastDict["payload"] = None
        else:
            broadcastDict["payload"] = None
                    
        broadcast = u"httpd_" + request.path[1:]
        self.logger.debug(f"Webhook to {broadcast} = {json.dumps(broadcastDict)}")
        indigo.server.broadcastToSubscribers(broadcast, json.dumps(broadcastDict))

    def do_POST(self):
        self.logger = logging.getLogger("Plugin.MyRequestHandler")
        client_host, client_port = self.client_address
        port = self.server.socket.getsockname()[1]
        self.logger.debug(f"MyRequestHandler: POST to port {port} from {client_host}:{client_port} for {self.path}")
        
        if not self.is_authorized():
            self.logger.debug(f"MyRequestHandler: Authorization failed")
            self.send_reply(401)
            return
                       
        request = urlparse(self.path)
        if request.path == "/setvar":
            self.do_setvar(request)
        
        elif "webhook" in request.path:
            self.do_webhook(request)
        
        else:
            self.logger.debug(f"MyRequestHandler: Unknown POST request: {request.path}")

        self.send_reply(200)

    def do_GET(self):
        self.logger = logging.getLogger("Plugin.MyRequestHandler")
        client_host, client_port = self.client_address
        port = self.server.socket.getsockname()[1]
        self.logger.debug(f"MyRequestHandler: GET to port {port} from {client_host}:{client_port} for {self.path}")

        if not self.is_authorized():
            self.send_reply(401)
            return

        request = urlparse(self.path)

        if request.path == "/setvar":
            self.do_setvar(request)

        elif "webhook" in request.path:
            self.do_webhook(request)
                
        else:
            self.logger.debug(f"MyRequestHandler: Unknown GET request: {request.path}")

        self.send_reply(200)


class Plugin(indigo.PluginBase):

    ########################################
    # Main Plugin methods
    ########################################
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.logLevel = int(self.pluginPrefs.get("logLevel", logging.INFO))
        self.indigo_log_handler.setLevel(self.logLevel)
        self.logger.debug(f"logLevel = {self.logLevel}")

        self.servers = {}
        self.triggers = {}
        self.proxy_data = {}
        self.next_test = time.time() + 60.0  # wait 60 seconds before testing
        self.threadLock = threading.Lock()  # for background connection test
        self.keepAlive = float(self.pluginPrefs.get('keepAlive', "60"))  * 60   # test interval in minutes
        self.logger.debug(f"keepAlive = {self.keepAlive}")

    def start_server(self, port, https=False, certfileName=None, keyfileName=None):
    
        if port == 0:
            return None

        if not https:
            try:
                server = MyHTTPServer(("", port), MyRequestHandler)
                server.timeout = 1.0
                self.logger.debug(f"Started HTTP server on port {port}")
                return server
                
            except Exception as e:
                self.logger.error(f"Unable to open port {port} for HTTP Server: {e} ")
                return None
        
        else:

            certfile = indigo.server.getInstallFolderPath() + '/' + certfileName
            if not os.path.isfile(certfile):
                self.logger.error(f"Certificate file missing, unable to start HTTPS server on port {port}")
                return None

            try:
                server = MyHTTPServer(("", port), MyRequestHandler)
                server.timeout = 1.0
            except Exception as e:
                self.logger.error(f"Unable to open port {port} for HTTPS Server: {e} ")
                return None

            if not keyfileName:
                keyfile = None
            else:
                keyfile = indigo.server.getInstallFolderPath() + '/' + keyfileName
                if not os.path.isfile(keyfile):
                    self.logger.error(f"Key file not found, unable to start HTTPS server on port {port}")
                    return None
            
            server.socket = ssl.wrap_socket(server.socket, keyfile=keyfile, certfile=certfile, server_side=True)
            self.logger.debug(f"Started HTTPS server on port {port}")
            return server

    def runConcurrentThread(self):

        try:
            while True:
                for server in list(self.servers.values()):
                    try:
                        server.handle_request()
                    except Exception as e:
                        self.logger.warning(f"{key}: Error on server.handle_request(): {e}")

                if time.time() > self.next_test:
                    self.next_test = time.time() + self.keepAlive
                    self.logger.debug("Starting Connection Keep Alive thread...")
                    testThread = threading.Thread(target=self.testConnections, args=())
                    testThread.start()           
                                                     
                self.sleep(0.1)

        except self.StopThread:
            pass

    def testConnections(self):

        if not self.threadLock.acquire(False):
            self.logger.warning("Keep Alive: Unable to test connections, process already running.")
            return

        self.logger.debug("Keep Alive: Connection Testing Started")

        for serverDevID in list(self.servers):
            serverDev = indigo.devices[serverDevID]
            
            url = f"{serverDev.pluginProps.get('protocol', 'http')}://127.0.0.1:{serverDev.address}/"
            
            self.logger.debug(f"{serverDev.name}: connection test = {url}")
            try:
                r = requests.get(url, timeout=1.0, verify=False)
            except Exception as err:
                self.logger.error(f"{serverDev.name}: connection test error = {err}")
                self.logger.debug(f"{serverDev.name}: connection test restarting device")
                self.deviceStopComm(indigo.devices[serverDevID])
                self.sleep(2)
                self.deviceStartComm(indigo.devices[serverDevID])
                        
            else:
                self.logger.debug(f"{serverDev.name}: connection test status = {r.status_code}")

        self.logger.debug("Keep Alive: Connection Testing Complete")
        self.threadLock.release()

    ####################

    def triggerStartProcessing(self, trigger):
        self.logger.debug(f"Adding Trigger {trigger.name} ({trigger.id})")
        assert trigger.id not in self.triggers
        self.triggers[trigger.id] = trigger

    def triggerStopProcessing(self, trigger):
        self.logger.debug(f"Removing Trigger {trigger.name} ({trigger.id})")
        assert trigger.id in self.triggers
        del self.triggers[trigger.id]

    ########################################
    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            self.logLevel = int(self.pluginPrefs.get("logLevel", logging.INFO))
            self.indigo_log_handler.setLevel(self.logLevel)
            self.logger.debug(u"logLevel = {}".format(self.logLevel))

            self.keepAlive = float(valuesDict.get('keepAlive', "60")) * 60  # test interval in minutes
            
    ########################################
    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.logger.debug(f"validateDeviceConfigUi typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        errorsDict = indigo.Dict()

        if typeId == 'serverDevice':
            try:
                port = int(valuesDict.get('address', '0'))
            except ValueError:
                errorsDict['address'] = "HTTP Port Number invalid"
            else:
                if port < 1024:
                    errorsDict['address'] = "HTTP Port Number invalid"
                    
            if valuesDict.get('protocol', 'http') == 'https':
                certfile = indigo.server.getInstallFolderPath() + '/' + valuesDict.get('certfileName', "")
                if not os.path.isfile(certfile):
                    self.logger.debug(f"validateDeviceConfigUi certfile not found: {certfile}")
                    errorsDict['certfileName'] = "Certificate file required for HTTPS protocol"

        elif typeId == 'proxyDevice':
            if not valuesDict.get('serverDevice', None):
                errorsDict['serverDevice'] = "Server Device required"
            
        self.logger.debug(f"validateDeviceConfigUi done - {len(errorsDict)} errors")
        
        if len(errorsDict) > 0:
            return False, valuesDict, errorsDict
        return True, valuesDict

    def deviceStartComm(self, dev):
        self.logger.info(f"{dev.name}: Starting {dev.deviceTypeId} Device {dev.id}")
                    
        if dev.deviceTypeId == 'serverDevice':
            port = int(dev.address)
            https = dev.pluginProps.get('protocol', 'http') == 'https'
            certfile = dev.pluginProps.get('certfileName', None)
            keyfile = dev.pluginProps.get('keyfileName', None)
            
            server = self.start_server(port, https=https, certfileName=certfile, keyfileName=keyfile)
            if server:
                digestRequired = dev.pluginProps.get('digestRequired', False)
                httpUser = dev.pluginProps.get('httpUser', None)
                httpPassword = dev.pluginProps.get('httpPassword', None)
                server.set_auth_params(httpUser, httpPassword, digestRequired)
                server.set_dev_id(dev.id)
                self.servers[dev.id] = server
  
            saved_states = json.loads(dev.pluginProps.get("saved_states", "{}"))
            state_list = []
            for key in saved_states:
                state_list.append({'key': key, 'value': saved_states[key]})
            dev.updateStatesOnServer(state_list)
          
        elif dev.deviceTypeId == 'proxyDevice':
            serverID = dev.pluginProps.get('serverDevice', None)
            if not serverID:
                self.logger.warning(u"{}: No Server Device specified".format(dev.name))
            
            webhook_info = self.getWebhookInfo(str(dev.id), serverID)
            self.logger.debug(u"{}: deviceStartComm, webhook_info = {}".format(dev.name, webhook_info))
            stateList = [
                            {'key': 'hook_url',  'value': webhook_info.get("hook_url", None)},
                            {'key': 'hook_name', 'value': webhook_info.get("hook_name", None)}
                        ]
            dev.updateStatesOnServer(stateList)

            indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd2", webhook_info["hook_name"], "webhook_proxy")

    def deviceStopComm(self, dev):
        self.logger.info(f"{dev.name}: Stopping {dev.deviceTypeId} Device {dev.id}")

        if dev.deviceTypeId == 'serverDevice':
            self.logger.threaddebug(f"{dev.name}: deviceStopComm device states: {dev.states}")

            server = self.servers[dev.id]
            del self.servers[dev.id]
            assassin = threading.Thread(target=server.server_close)
            assassin.daemon = True
            assassin.start()            
            
        elif dev.deviceTypeId == 'proxyDevice':
            serverID = dev.pluginProps.get('serverDevice', None)

            webhook_info = self.getWebhookInfo(str(dev.id), serverID)
            self.logger.debug(f"{dev.name}: deviceStartComm, webhook_info = {webhook_info}")
            indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd2", webhook_info["hook_name"], "CallbackNOP")
           
    def didDeviceCommPropertyChange(self, oldDevice, newDevice):
        if newDevice.deviceTypeId == 'serverDevice':
            for prop in newDevice.pluginProps:
                if prop in ['saved_states']:          # list of properties to ignore
                    pass
                elif newDevice.pluginProps.get(prop, None) != oldDevice.pluginProps.get(prop, None):
                    self.logger.threaddebug(
                        f"{newDevice.name}: didDeviceCommPropertyChange prop {prop}: {oldDevice.pluginProps.get(prop, None)}->{newDevice.pluginProps.get(prop, None)}")
                    return True
            self.logger.threaddebug(f"{newDevice.name}: didDeviceCommPropertyChange no changes")
            
        elif newDevice.deviceTypeId == 'proxyDevice':
            if newDevice.pluginProps["serverDevice"] != oldDevice.pluginProps["serverDevice"]:
                return True
                
        return False
        
    ########################################
    #
    # callback for state list changes, called from stateListOrDisplayStateIdChanged()
    #
    ########################################

    def getDeviceStateList(self, device):
        state_list = indigo.PluginBase.getDeviceStateList(self, device)
        self.logger.threaddebug(f"{device.name}: getDeviceStateList, base state_list = {state_list}")
        if device.deviceTypeId != "serverDevice":
            return state_list
            
        saved_states = json.loads(device.pluginProps.get("saved_states", "{}"))
        for key in saved_states:
            dynamic_state = self.getDeviceStateDictForStringType(str(key), str(key), str(key))
            state_list.append(dynamic_state)
        
        if device.id in self.servers:

            try:
                device_states = self.servers[device.id].state_list
                if device_states and len(device_states) > 0:
                    for item in device_states:
                        key = item['key']
                        value = item['value']
                        new_state = self.getDeviceStateDictForStringType(str(key), str(key), str(key))
                        self.logger.threaddebug(f"{device.name}: getDeviceStateList, adding String state {key}, value {value}")
                        state_list.append(new_state)
            except Exception as e:
                pass
                
        self.logger.threaddebug(f"{device.name}: getDeviceStateList, final state_list = {state_list}")
        return state_list

    def webhook_proxy(self, hookdata_json):

        hook_data = json.loads(hookdata_json)
        
        proxy_dev = indigo.devices[int(hook_data["request"]["path"][9:])]
        self.proxy_data[proxy_dev.id] = hook_data
        
        proxy_dev.updateStateOnServer(key='hookdata_json', value=hookdata_json)

        for triggerId, trigger in sorted(self.triggers.iteritems()):
            self.logger.debug(f"Checking Trigger {trigger.name} ({trigger.id})")
            if trigger.pluginProps["proxyDevice"] == str(proxy_dev.id):
                self.logger.debug(f"Executing Trigger {trigger.name} ({trigger.id})")
                indigo.trigger.execute(trigger)

    def CallbackNOP(self, hook_data):
        pass

    def resetDeviceStatesAction(self, pluginAction):
        deviceId = int(pluginAction.props["targetDevice"])
        self.resetDeviceStates(indigo.devices[deviceId])
        
    def resetDeviceStatesMenu(self, valuesDict, typeId):
        try:
            deviceId = int(valuesDict["targetDevice"])
        except Exception as e:
            self.logger.error("Bad Device specified for Reset Device operation")
            return False

        self.resetDeviceStates(indigo.devices[deviceId])
        return True
      
    @staticmethod
    def resetDeviceStates(device):
        newProps = device.pluginProps
        newProps["saved_states"] = "{}"
        device.replacePluginPropsOnServer(newProps)
        device.stateListOrDisplayStateIdChanged()    

    ########################################
    # Actions
    ########################################

    def getWebhookDataAction(self, pluginAction, device, callerWaitingForResult=True):

        try:
            hook_data = self.proxy_data[device.id]
            return hook_data
        except Exception as e:
            return None

    def getWebhookInfoAction(self, pluginAction, device, callerWaitingForResult=True):

        return self.getWebhookInfo(pluginAction.props.get(u"name", None), pluginAction.props.get("server", None))

    def getWebhookInfo(self, callerName, serverID):

        if not callerName or not serverID:
            self.logger.warning("getWebhookInfo failed, caller name or server deviceID not provided")
            return None

        info = {"hook_name": "httpd_webhook-" + callerName}
        
        serverDev = indigo.devices.get(int(serverID), None)
        if not serverDev:
            self.logger.warning(u"getWebhookInfo failed, invalid Server DeviceID")
            return None
        
        ddnsName = self.pluginPrefs.get('ddnsName', None)
        if not ddnsName:
            self.logger.warning(u"getWebhookInfo failed, invalid ddnsName")
            return None
        
        if len(serverDev.pluginProps.get('httpPassword', None)) != 0:
            auth = f"{serverDev.pluginProps.get('httpUser', '')}:{serverDev.pluginProps.get('httpPassword', '')}@"
        else:
            auth = ''
                    
        port = int(serverDev.pluginProps.get('address', 0))
        if not port:
            self.logger.warning("getWebhookInfo failed, invalid port number")
            return None
        
        protocol = serverDev.pluginProps.get('protocol', None)
        if not protocol:
            self.logger.warning("getWebhookInfo failed, invalid protocol")
            return None

        info[u"hook_url"] = f"{protocol}://{auth}{ddnsName}:{port}/webhook-{callerName}"
        self.logger.debug(f"getWebhookInfo, info = {info}")

        return info
