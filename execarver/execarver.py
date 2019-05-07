from optparse import OptionParser
from scapy.all import *

parser = OptionParser()
parser.add_option("-i",  dest = "interface", default = "eth0")
parser.add_option("-r", dest = "tracefile")
options, args = parser.parse_args()
filters = ''
for i in args:
    filters = filters + i + ' '

filters = filters.rstrip()

if options.tracefile:
    print("Reading TraceFile")
    try:
        if args:
            pkts = sniff(offline = options.tracefile, filter = filters)
        else:
            pkts = sniff(offline = options.tracefile)
    except:
	print("File not found or of invalid type")
	quit()
if options.interface and not options.tracefile:
    print("Sniffing Packets")
    if args:
        pkts = sniff(iface = options.interface, filter = filters)
    else:
        pkts = sniff(iface = options.interface)


sessions = pkts.sessions()
for k,p  in sessions.iteritems():
	if 'TCP' in str(k):
		for v in p:
			if 'filename*' in str(v.getlayer(TCP).payload):
				pay = str(v.getlayer(TCP).payload)
        			find = pay[pay.index('filename*'):]
        			filename = find[find.index("''") + 2:find.index("\r")]

        			num = pay[pay.index("Content-Length:"):]
        			size = num[:num.index("\r")]
        			print "File-Name: " + filename + "  " + size
				f = open(filename,'wb')
				sub = ""
				for packets in sessions[k][1:]:
					if 'filename*' in str(packets[TCP].payload):
						found = str(packets[TCP].payload)
						sub = found[found.index("MZ"):]
						
					else:
						sub = sub + str(packets[TCP].payload)
				f.write(bytes(sub))
				f.close()

					
					
				


		


		
      

