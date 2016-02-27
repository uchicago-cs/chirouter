#
#  chirouter - A simple, testable IP router
#
#  This module contains the POX controller which provides the switches
#  and routers in chirouter's network. The switches are controlled entirely
#  here, but the router's behavior is determined by sending the Ethernet
#  frames to the chirouter program, which can then send Ethernet frames
#  back to the POX controller on a specific interface.
#
#  This code draws heavily from the POX controller originally included in the
#  Simple Router assignment included in the Mininet project 
#  (https://github.com/mininet/mininet/wiki/Simple-Router) which,
#  in turn, is based on a programming assignment developed at Stanford
# (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
#
#  The original POX controller in the Simple Router assignment was
#  written by James McCauley and had the following copyright/license:
#
#  # # #
#  Copyright 2012 James McCauley
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
# 
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  # # #

#  The current version of this code is available under this license:
#
#  Copyright (c) 2016, The University of Chicago
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  - Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
#  - Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  - Neither the name of The University of Chicago nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

import SocketServer
import threading
import socket
import string
import binascii


log = core.getLogger()

class SwitchController (object):
  """
  A SwitchController object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

  def _handle_PacketIn (self, event):

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      #og.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    self.act_like_hub(packet, packet_in)

  def shutdown_controller(self):
    pass

class SRConnectionHandler(object):
  def __init__(self, conn, server):
    self.conn = conn
    self.server = server
    self.running = True
    self.rcv_thread = threading.Thread(target = self.rcvloop)
    self.rcv_thread.daemon = False
    self.rcv_thread.start()
    self.send_lock = threading.Lock()
    log.info("Connected to chirouter")

  def sendmsg(self, message):
    try:          
        self.send_lock.acquire()
        sent = 0
        while sent < len(message):
          delta = self.conn.send(message)
          if (delta == 0):
            self.stop()
            self.send_lock.release()
            break
          sent = sent + delta
    
        self.send_lock.release()
    except socket.error, e:
        log.error("Socket error: %s" % e)
        self.stop()

  def contains_full_msg(self, message):
    prefix = -1
    try:
      prefix = string.index(message, " ")
    except ValueError:
      return -1
    if prefix == -1:
      return -1
    length = int(message[:prefix])
    if len(message) >= prefix + length + 1:
      return prefix
    else :
      return -1

  def rcvloop(self):
    received = ""
    log.debug("Starting rcv loop")
    try:
      while(self.running):
        cur_msg_len = self.contains_full_msg(received)
        if cur_msg_len != -1:
          test, rest = self.split_msg_on_index(received, cur_msg_len)
          self.server.controller.forward_packet(test)
          received = rest
        else:
          temp = self.conn.recv(4096)
          received = received + temp
    finally:
      self.conn.close()
      log.debug("Ending rcv loop")
      self.server.remove_connection(self)

  def split_msg_on_index(self, message, index):
    length = int(message[:index])
    return (message[index+1:index+length+1], message[index+length+1:])

  def get_split_string(self, message):
    prefix = -1
    try:
      prefix = string.index(message, " ")
    except ValueError:
      return (None, message)
    if prefix == -1:
      return (None, message)
    length = int(message[:prefix])
    if len(message) >= prefix + length:
      return (message[prefix+1:prefix+length+1], message[prefix+length+1:])
    else :
      return (None, message)

  def stop(self):
    self.running = False


class SRServer(object):
  def __init__(self, controller):
    self.connections = []
    self.connections_lock = threading.Lock()
    self.controller = controller

  def add_connection(self, conn):
    self.connections_lock.acquire()
    new_conn = SRConnectionHandler(conn, self)
    self.connections.append(new_conn)
    self.connections_lock.release()
    return new_conn

  def send_message(self, message):
    self.connections_lock.acquire()
    for c in self.connections:
      c.sendmsg(message)
    self.connections_lock.release()

  def remove_connection(self, handler):
    self.connections_lock.acquire()
    if handler in self.connections:
      self.connections.remove(handler)
      handler.stop()
    self.connections_lock.release()

  def shutdown(self):
    for connection in self.connections:
      self.remove_connection(connection)

class SRController(object):
  def __init__ (self, connection, ifaces):
    log.info("Creating new Controller")
    self.connection = connection
    self.accepting = True
    self.ifaces = ifaces
    for k,v in ifaces.items():
        log.info("Adding interface %s with IP %s" % (k,v))
    self.server = None
    
    self.server_thread = threading.Thread(target = self.start_socket_server)
    self.server_thread.daemon = True
    self.server_thread.start()

    # This binds our PacketIn event listener
    connection.addListeners(self)
    
  def shutdown_controller(self):
    self.accepting = False
    if (self.server is not None):
      self.server.shutdown()

  def forward_packet(self, data):
    """ data contains ethernet iface ' ' packet"""
    index = string.index(data, " ")
    iface = data[:index]
    ethernet_data = data[index+1:]

    msg = of.ofp_packet_out()
    msg.data = ethernet_data
    msg.in_port = of.OFPP_NONE
    output_port = self.find_port_from_iface(iface)
    action = of.ofp_action_output(port = output_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def find_iface_from_number(self, port_no):
    for port in self.connection.features.ports:
      if port.port_no == port_no:
        return port.name
    return "no iface found"

  def find_port_from_iface(self, iface):
    target = "router"+str(self.connection.dpid)+"-"+iface
    for port in self.connection.features.ports:
      if port.name == target:
        return port.port_no
    return -1

  def send_message_wrapper(self, msg_type, message):
    output = self.format_message_wrapper(msg_type, message)
    self.server.send_message(output)

  def format_message_wrapper(self, msg_type, message):
    contents = str(msg_type)+message;
    output = str(len(contents))+" "+contents;
    return output;

  def forward_to_router (self, packet, packet_in):
    if (self.server is None):
      return
    interface = "eth0"
    try:
      interface = self.find_iface_from_number(packet_in.in_port).split("-")[1]
    except IndexError:
      return #The other switch won't shut up, for whatever reason.
    finally:
      pass
    var = interface+" "+packet.pack()
    self.send_message_wrapper(0, var)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    self.forward_to_router(packet, packet_in)

  def start_socket_server(self):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    log.debug("Starting connections")
    sock.bind(('', self.connection.dpid))
    sock.listen(5)
    self.server = SRServer(self)
    while(self.accepting):
      c, addr = sock.accept()
      log.debug("got connection from %s" % (addr,))
      new_conn_handler = self.server.add_connection(c)
      for port in self.connection.features.ports:
        try:
          iface = port.name.split("-")[1]
          hardware_addr = port.hw_addr
          ip = self.ifaces[iface]
          message = iface+" "+hardware_addr.toRaw()+" "+ip+" ";
          new_conn_handler.sendmsg(self.format_message_wrapper(1, message))
        except IndexError:
          pass
      new_conn_handler.sendmsg(self.format_message_wrapper(2, "done with ifaces"))

sr_controller_list = {}
def launch(topology_dir):
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s (dpid: %i)" % (event.connection, event.connection.dpid))
    controller = None
    f = open("{}/router_dpid_list".format(topology_dir), "r").readlines()
    dpids = map(int, f)    
    if (event.connection.dpid in dpids):
        iface_file = open("{}/itable{}".format(topology_dir, str(event.connection.dpid)), "r")
        ifaces = {}
        for line in iface_file:
          data = line.split(" ")
          ifaces[data[1][:-1]] = data[0]       
        controller = SRController(event.connection, ifaces)
        sr_controller_list[event.connection] = controller
        log.debug("Made new SRController on port " + str(event.connection.dpid))
    else:
        controller = SwitchController(event.connection)
        log.debug("Made new SwitchController")
    

  def stop_switch (event):
    log.debug("Stopping %s" % (event.connection,))
    if (event.connection in sr_controller_list):
      sr_controller_list[event.connection].shutdown_controller()

  core.openflow.miss_send_len = 0xffff
  core.openflow.addListenerByName("ConnectionUp", start_switch)
  core.openflow.addListenerByName("ConnectionDown", stop_switch)
