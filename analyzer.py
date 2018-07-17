#!/usr/bin/python
import collections
import csv
import datetime
import ipaddr
import sys
import argparse
from sqlitedict import SqliteDict

_FLOW_FIELDS = [
    "ts",
    "ip_protocol",
    "state",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "src_tx",
    "dst_tx",
]

# counters per IP tuple
flowCount = SqliteDict('',autocommit=True)
# Amount of data shared
session_total_bytes =  SqliteDict('./session_total.sqlite',autocommit=True)
session_src_bytes =  SqliteDict('./session_src.sqlite',autocommit=True)
session_dst_bytes =  SqliteDict('./session_dst.sqlite',autocommit=True)
session_flow_count =  SqliteDict('./session_flow.sqlite',autocommit=True)
oneway_request_count =  SqliteDict('./oneway_req.sqlite',autocommit=True)
tcpreq_count =  SqliteDict('./tcp_req.sqlite',autocommit=True)

class Flow(collections.namedtuple("Flow", _FLOW_FIELDS)):
    __slots__ = ()

    @staticmethod
    def from_csv(e):
        """
        Factory method.
        Construct Flow instances from a CSV-representation of a flow.
        """

        flow = Flow(ts=datetime.datetime.strptime(e[0], "%Y-%m-%d %H:%M:%S"),
                    ip_protocol=e[1],
                    state=e[2],
                    src_ip=ipaddr.IPAddress(e[3]),
                    src_port=int(e[4]),
                    dst_ip=ipaddr.IPAddress(e[5]),
                    dst_port=int(e[6]),
                    src_tx=int(e[7]),
                    dst_tx=int(e[8]))
        return flow

    @staticmethod
    def flow_segregate(e, flow):
        """
        Factory method.
        Fill the counting dictionaries for anamoly analysis
        """

        #flowCount[IPTuple] = flowCount.get(IPTuple, 0) + 1
        ts = flow.ts
        state = flow.state
        src_tx = flow.src_tx
        dst_tx = flow.dst_tx
        protocol = flow.ip_protocol
        ip_tuple = str(flow.src_ip) + " " + str(flow.src_port) + " " + str(flow.dst_ip) + " " + str(flow.dst_port)
        oneway_request_count[ip_tuple] = oneway_request_count.get(ip_tuple,0) + 1

        # Bytes per session. Session between two IPs alternating as src and dst.
        session_tuple = ''
        if flow.src_ip < flow.dst_ip:
            session_tuple = str(flow.src_ip) + " " + str(flow.src_port) + " " + str(flow.dst_ip) + " " + str(flow.dst_port)
        else:
            session_tuple = str(flow.dst_ip) + " " + str(flow.dst_port) + " " + str(flow.src_ip) + " " + str(flow.src_port)

        # TODO take care of different protocols and state
        session_src_bytes[session_tuple] = session_src_bytes.get(session_tuple, 0) + int(src_tx)
        session_dst_bytes[session_tuple] = session_dst_bytes.get(session_tuple, 0) + int(dst_tx)
        session_total_bytes[session_tuple] = session_total_bytes.get(session_tuple, 0) + int(src_tx) + int(dst_tx)
        session_flow_count[session_tuple] = session_flow_count.get(session_tuple, 0) + int(1)

        #number of remote TCP connections to the same srcip:src:port
        # TODO Consider time duration between the suspected syn-flood attacks, need more info on wait expiry, renews, etc
        # DDoS attack might have different IPs performing synflooding at the same host
        if state == "connecting" and protocol == "tcp":
            tcp_syn_tuple = str(flow.src_ip)
            tcpreq_count[tcp_syn_tuple] = tcpreq_count.get(tcp_syn_tuple, 0) + 1

_ALERT_FIELDS = [
    "name",
    "evidence",
]

Alert = collections.namedtuple("Alert", _ALERT_FIELDS)


class Analyzer(object):

    def __init__(self, slimit, dlimit, tlimit, sessions, requests, ports):
        self.__num_flows = 0
        self.__src_limit = slimit
        self.__dst_limit = dlimit
        self.__total_limit = tlimit
        self.__sessions_limit = sessions
        self.__requests_limit = requests
        self.__ports_limit = ports
        self.__alerts = []

    #@classmethod
    def process(self):
        """
        Process a flow.

        :param Flow flow: a data flow record
        """
       # self.__num_flows += 1

        # TODO Detecting DoS
        # Changes or number of flows in the same address
        # EVery X min, count flows with sampling 1/Y during Z sec, if no. of flows is > N = DOS attack
        # That is, count flows in X min with sampling 1/Y per Z sec and check with threshold

        # Unusual outbound traffic
        for session_tuple,sharedData in session_src_bytes.items():
            if sharedData > self.__src_limit:
                self.__alerts.append(Alert(name="Abnormal amount of data transmitted",
                        evidence=[session_tuple, sharedData]))
        # Unusual inbound traffic
        for session_tuple,sharedData in session_dst_bytes.items():
            if sharedData > self.__dst_limit:
                self.__alerts.append(Alert(name="Abnormal amount of data received",
                        evidence=[session_tuple, sharedData]))
        # Unusual total traffic size
        for session_tuple,sharedData in session_total_bytes.items():
            if sharedData > self.__total_limit:
                self.__alerts.append(Alert(name="Abnormal amount of data shared",
                        evidence=[session_tuple, sharedData]))
        # Unusual number of repeated sessions between two IPs
        for session_tuple,count in session_flow_count.items():
            if count > self.__sessions_limit:
                self.__alerts.append(Alert(name="Abnormal number of sessions established",
                        evidence=[session_tuple, count]))
        # Unusual number of incoming or outgoing requests for same IP
        for IPtuple,count in oneway_request_count.items():
            if count > self.__requests_limit:
                self.__alerts.append(Alert(name="Abnormal number of requests transmitted/received",
                        evidence=[IPtuple, count]))

        # Unusual number of open connections on a host
        for SYNtuple,count in tcpreq_count.items():
            if count > self.__ports_limit:
                self.__alerts.append(Alert(name="Abnormal number of ports open in host",
                        evidence=[SYNtuple, count]))


    @property
    def alerts(self):
        """
        Return the alerts that were generated during the processing of flows.

        :return: a list of alerts
        :rtype: List[Alert]
        """

        '''
        Kind of output
        Severity, duration, direction (in/out), class
        '''
        return self.__alerts

def main(argv):
    '''
    Handle input requests here.
    Let the user define what should be threshold
    Have some default values
    '''

    ap = argparse.ArgumentParser()
    ap.add_argument("-s", "--src_limit", type=int, required=True, default=100000, help="Download limit")
    ap.add_argument("-d", "--dst_limit", type=int, required=True, default=100000,help="Upload limit")
    ap.add_argument("-t", "--total_limit", type=int, required=True, default=100000,help="Data share limit")
    ap.add_argument("-u", "--sessions_limit", type=int, required=False, default=1000,help="Uniq sessions limit")
    ap.add_argument("-r", "--requests_limit", type=int, required=False, default=1000,help="One way requests limit")
    ap.add_argument("-p", "--ports_limit", type=int, required=False, default=1000,help="One way half-open requests limit per second")
    args = ap.parse_args()

    analyzer = Analyzer(args.src_limit, args.dst_limit, args.total_limit,
            args.sessions_limit, args.requests_limit, args.ports_limit)
    file_name = sys.stdin
    '''
	currentDataSize = fileSize(file_name)
	while currentDataSize != 0:

	Rolling buffer:
	Buffer size keeps changing depending on the availability
	So that it does not impact other system applications.
	Change the size not in every iterations.

		maxBuffer = getAvailRam() / 10  # check this formula
		if currentDataSize <= maxBuffer:
			loadSize = currentDataSize
			currentDataSize = 0
			break
		else:
			loadSize = maxBuffer
			currentDataSize = currentDataSize - loadSize
    '''
    reader = csv.reader(sys.stdin) #, currentDataSize) # check to move the pointer
    #incremental analysis
    for raw_flow in reader:
            flow = Flow.from_csv(raw_flow)
            Flow.flow_segregate(raw_flow, flow)
    analyzer.process()

    for alert in analyzer.alerts:
            print alert.name
            print "\n".join("\t{}".format(e) for e in alert.evidence)

    session_total_bytes.close()
    session_src_bytes.close()
    session_dst_bytes.close()
    session_flow_count.close()
    oneway_request_count.close()
    tcpreq_count.close()
    #TODO Statistical Analysis
    #TODO Send the analysis to csv file: suspicious/vulnerable internal/external hosts.
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
