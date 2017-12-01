import queue
import threading
import sys


## wrapper class for a queue of packets
class Interface:
    ## @param maxsize - the maximum size of the queue storing packets
    def __init__(self, maxsize=0):
        self.in_queue = queue.Queue(maxsize)
        self.out_queue = queue.Queue(maxsize)
    
    ##get packet from the queue interface
    # @param in_or_out - use 'in' or 'out' interface
    def get(self, in_or_out):
        try:
            if in_or_out == 'in':
                pkt_S = self.in_queue.get(False)
                # if pkt_S is not None:
                #     print('getting packet from the IN queue')
                return pkt_S
            else:
                pkt_S = self.out_queue.get(False)
                # if pkt_S is not None:
                #     print('getting packet from the OUT queue')
                return pkt_S
        except queue.Empty:
            return None
        
    ##put the packet into the interface queue
    # @param pkt - Packet to be inserted into the queue
    # @param in_or_out - use 'in' or 'out' interface
    # @param block - if True, block until room in queue, if False may throw queue.Full exception
    def put(self, pkt, in_or_out, block=False):
        if in_or_out == 'out':
            # print('putting packet in the OUT queue')
            self.out_queue.put(pkt, block)
        else:
            # print('putting packet in the IN queue')
            self.in_queue.put(pkt, block)
            
        
## Implements a network layer packet.
class NetworkPacket:
    ## packet encoding lengths 
    dst_S_length = 5
    prot_S_length = 1
    
    ##@param dst: address of the destination host
    # @param data_S: packet payload
    # @param prot_S: upper layer protocol for the packet (data, or control)
    def __init__(self, dst, prot_S, data_S):
        self.dst = dst
        self.data_S = data_S
        self.prot_S = prot_S
        
    ## called when printing the object
    def __str__(self):
        return self.to_byte_S()
        
    ## convert packet to a byte string for transmission over links
    def to_byte_S(self):
        byte_S = str(self.dst).zfill(self.dst_S_length)
        if self.prot_S == 'data':
            byte_S += '1'
        elif self.prot_S == 'control':
            byte_S += '2'
        else:
            raise('%s: unknown prot_S option: %s' %(self, self.prot_S))
        byte_S += self.data_S
        return byte_S
    
    ## extract a packet object from a byte string
    # @param byte_S: byte string representation of the packet
    @classmethod
    def from_byte_S(self, byte_S):
        dst = byte_S[0 : NetworkPacket.dst_S_length].strip('0')
        prot_S = byte_S[NetworkPacket.dst_S_length : NetworkPacket.dst_S_length + NetworkPacket.prot_S_length]
        if prot_S == '1':
            prot_S = 'data'
        elif prot_S == '2':
            prot_S = 'control'
        else:
            raise('%s: unknown prot_S field: %s' %(self, prot_S))
        data_S = byte_S[NetworkPacket.dst_S_length + NetworkPacket.prot_S_length : ]        
        return self(dst, prot_S, data_S)
    

    

## Implements a network host for receiving and transmitting data
class Host:
    
    ##@param addr: address of this node represented as an integer
    def __init__(self, addr):
        self.addr = addr
        self.intf_L = [Interface()]
        self.stop = False #for thread termination
    
    ## called when printing the object
    def __str__(self):
        return self.addr
       
    ## create a packet and enqueue for transmission
    # @param dst: destination address for the packet
    # @param data_S: data being transmitted to the network layer
    def udt_send(self, dst, data_S):
        p = NetworkPacket(dst, 'data', data_S)
        print('%s: sending packet "%s"' % (self, p))
        self.intf_L[0].put(p.to_byte_S(), 'out') #send packets always enqueued successfully
        
    ## receive packet from the network layer
    def udt_receive(self):
        pkt_S = self.intf_L[0].get('in')
        if pkt_S is not None:
            print('%s: received packet "%s"' % (self, pkt_S))
       
    ## thread target for the host to keep receiving data
    def run(self):
        print (threading.currentThread().getName() + ': Starting')
        while True:
            #receive data arriving to the in interface
            self.udt_receive()
            #terminate
            if(self.stop):
                print (threading.currentThread().getName() + ': Ending')
                return
        


## Implements a multi-interface router
class Router:
    
    ##@param name: friendly router name for debugging
    # @param cost_D: cost table to neighbors {neighbor: {interface: cost}}
    # @param max_queue_size: max queue length (passed to Interface)
    def __init__(self, name, cost_D, max_queue_size):
        self.stop = False #for thread termination
        self.name = name
        #create a list of interfaces
        self.intf_L = [Interface(max_queue_size) for _ in range(len(cost_D))]
        #save neighbors and interfeces on which we connect to them
        self.cost_D = cost_D    # {neighbor: {interface: cost}}
        #TODO: set up the routing table for connected hosts
        self.rt_tbl_D = {}      # {destination: {router: cost}}
        print('%s: Initialized routing table' % self)
        self.init_destinations()
        self.ford_table = self.bellman_ford(self.rt_tbl_D)
        self.print_routes()


    ## called when printing the object
    def __str__(self):
        return self.name


    ## look through the content of incoming interfaces and 
    # process data and control packets
    def process_queues(self):
        for i in range(len(self.intf_L)):
            pkt_S = None
            #get packet from interface i
            pkt_S = self.intf_L[i].get('in')
            #if packet exists make a forwarding decision
            if pkt_S is not None:
                p = NetworkPacket.from_byte_S(pkt_S) #parse a packet out
                if p.prot_S == 'data':
                    self.forward_packet(p,i)
                elif p.prot_S == 'control':
                    self.update_routes(p, i)
                else:
                    raise Exception('%s: Unknown packet type in packet %s' % (self, p))
            

    ## forward the packet according to the routing table
    #  @param p Packet to forward
    #  @param i Incoming interface number for packet p
    def forward_packet(self, p, i):
        try:
            # TODO: Here you will need to implement a lookup into the 
            # forwarding table to find the appropriate outgoing interface
            # for now we assume the outgoing interface is 1
            self.intf_L[1].put(p.to_byte_S(), 'out', True)
            print('%s: forwarding packet "%s" from interface %d to %d' % \
                (self, p, i, 1))
        except queue.Full:
            print('%s: packet "%s" lost on interface %d' % (self, p, i))
            pass


    ## send out route update
    # @param i Interface number on which to send out a routing update
    ## send out route update
    # @param i Interface number on which to send out a routing update
    def send_routes(self, i):
        # TODO: Send out a routing table update
        keys = self.ford_table.keys()
        route_string = self.name+'@'
        for key in keys:
            route_string += str(key)+':'+str(self.ford_table[key][1])+','
        p = NetworkPacket(0, 'control', route_string[:-1])
        try:
            print('%s: sending routing update "%s" from interface %d' % (self, p, i))
            self.intf_L[i].put(p.to_byte_S(), 'out', True)
        except queue.Full:
            print('%s: packet "%s" lost on interface %d' % (self, p, i))
            pass


    ## forward the packet according to the routing table
    #  @param p Packet containing routing information
    def update_routes(self, p, i):
        #TODO: add logic to update the routing tables and
        resend = False
        print('%s: Received routing update %s from interface %d' % (self, p, i))
        rcvd_from,rcvd_table = p.data_S.split('@')
        rcvd_table = rcvd_table.split(',')
        for r in rcvd_table:
            dest,cost = r.split(':')
            cost = int(cost)
            if dest in self.rt_tbl_D.keys():
                if rcvd_from not in self.rt_tbl_D[dest].keys():
                    resend = True
                elif self.rt_tbl_D[dest][rcvd_from] != cost:
                    resend = True
                self.rt_tbl_D[dest][rcvd_from] = cost
            else:
                self.rt_tbl_D[dest] = {rcvd_from:cost}
                resend = True
        self.ford_table = self.bellman_ford(self.rt_tbl_D)
        if resend:
            for i in range(len(self.intf_L)):
                self.send_routes(i)

    ## Print routing table
    def print_routes(self):
        #TODO: print the routes as a two dimensional table
        keys = self.rt_tbl_D
        router_names = [key for key in keys if 'R' in key]

        print(' '+'_'*(len(keys)*3+3))
        header = '|'+self.name+' |'
        for key in keys:
            header += key+'|'
        print(header)
        print(' ' + '-'*(len(keys)*3+3))
        for r in router_names:
            temp = '|'+r+' |'
            for key in keys:
                if r in self.rt_tbl_D[key].keys():
                    temp += str(self.rt_tbl_D[key][r])+' |'
                elif self.name == r and key in self.ford_table.keys():
                    temp += str(self.ford_table[key][1])+' |'
                else:
                    temp += '? |'
            print(temp)


    def init_destinations(self):
        keys = self.cost_D.keys()
        self.rt_tbl_D[self.name] = {self.name:0}
        for key in keys:
            self.rt_tbl_D[key] = {self.name:self.cost_D[key][1]}

    # Here is bellman_ford done as correctly as I can get it
    # aka im pretty sure its 99.9999% correct
    # basically its more correct than all the terrible/incorrect versions
    # of it available on github
    def bellman_ford(self, rt: {}):
        keys = rt.keys()
        router_names, host_names = [],[]
        new_table = None
        for key in keys:
            if 'R' in key:
                router_names.append(key)
            else:
                host_names.append(key)

        root = self.name
        kn_table = {root:(root,0)}
        visited = []

        for i in range(len(rt)):
            known_keys = list(kn_table.keys())
            for known in known_keys:
                if known not in visited:
                    known_cost = kn_table[known][1]
                    edges = self.get_edges(known, rt) # returns edges in [node, cost_to]
                    for edge in edges:
                        if edge[0] not in kn_table.keys():
                            kn_table[edge[0]] = (known,known_cost+edge[1])
                        else:
                            new_cost = known_cost+edge[1]
                            if new_cost < kn_table[edge[0]][1]:
                                kn_table[edge[0]] = (known,new_cost)
                    visited.append(known)

        new_table = kn_table
        return new_table

    def get_edges(self, root, rt:{str:{}}):
        edges = []
        keys = rt.keys()
        for key in keys:
            if root in rt[key].keys():
                edges.append((key,rt[key][root]))
        return edges






    ## thread target for the host to keep forwarding data
    def run(self):
        print (threading.currentThread().getName() + ': Starting')
        while True:
            self.process_queues()
            if self.stop:
                print (threading.currentThread().getName() + ': Ending')
                return 