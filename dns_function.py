#!/usr/bin/env python
import socket,struct,time,array,select,sqlite3
def _construct(id, size):
	header = struct.pack('bbHHh', 8, 0, 0,0, 0+id)
	size -= struct.calcsize("d")
	rest = size * "X"
	data = struct.pack("d", time.time()) + rest.encode()
	packet = header + data
	checksum = _in_cksum(packet)
	header = struct.pack('bbHHh', 8, 0, checksum, 0,0+id)
	packet = header + data 
	return packet
def _in_cksum(packet):
	if len(packet) & 1:
		packet = packet + '\0'
	words = array.array('h', packet) 
	sum = 0
	for word in words:
		sum += (word & 0xffff) 
	hi = sum >> 16 
	lo = sum & 0xffff 
	sum = hi + lo
	sum = sum + (sum >> 16)
	return (~sum) & 0xffff
def get_delay(address):#only ip
	packet = _construct(1, 16)
	pingSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.getprotobyname("icmp"))
	starttime=int(time.time()*1000)
	pingSocket.sendto(packet,(address,1))
	select.select([pingSocket], [], [], 1)
	pingSocket.close()
	return(int(time.time()*1000)-starttime)
def avarage_delay(address,time=100):
	time1=get_delay(address)
	i=1
	t_time=time1
	for i in range(time//time1):
		time1=get_delay(address)
		t_time+=time1
	return(t_time/i)
def analysis(conn,domain,server="114.114.114.114"):
	ip_arr=[]
	address_arr=[]
	search=b""
	addr=(server,53)
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	request_data=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+domain+b"\x00\x00\x01\x00\x01"
	s.sendto(request_data,addr)
	data,addr=s.recvfrom(2048)
	if not data:
		return False
	i=12
	while data[i:i+1]!=b'\x00':
		i+=1
	amount_of_answer=int.from_bytes(data[7:8],byteorder='big')+int.from_bytes(data[9:10],byteorder='big')+int.from_bytes(data[11:12],byteorder='big')
	#print(amount_of_answer)
	#amount_of_answer=12
	for i2 in range(amount_of_answer):
		data_lenth=int.from_bytes(data[i+15:i+17],byteorder='big')
		#print(data_lenth)
		if data_lenth==4:
			ttl=int.from_bytes(data[i+13:i+15],byteorder='big')
			#print(ttl)
			address=data[i+17:i+17+data_lenth]
			address_arr.append(address)
			ip=""
			
			for ip_int in address:
				ip+=str(ip_int)+"."
			ip_arr.append(ip[:-1])
			ip_arr.append(ttl)
		i+=data_lenth+12
	
	s.close()
	address_arr.sort()
	for i in address_arr: #组合数组
		search+=i
	cursor=conn.cursor()
	#cursor.execute("INSERT INTO request_list (domain,result) VALUES (?,?)",[sqlite3.Binary(domain),sqlite3.Binary(search)]);
	#conn.commit()
	cursor.execute("SELECT result,best FROM request_list WHERE domain=?",[sqlite3.Binary(domain)])
	
	sql_result=cursor.fetchone()
	
	if not sql_result:
		print("查找失败，写入数据库")
		cursor.execute("INSERT INTO request_list (domain,result) VALUES (?,?)",[sqlite3.Binary(domain),sqlite3.Binary(search)])
		conn.commit()
	else:
		#print("数据库有记录，比对记录")
		if sql_result[0]==search and sql_result[1]!=None:
			#print("对比成功，直接返回")
			i=0
			while ip_arr[i]!=sql_result[1]:
				i+=2
			return ip_arr[i],ip_arr[i+1]
		if sql_result[0]!=search:
			cursor.execute("UPDATE request_list set result=? where domain=?",[sqlite3.Binary(search),sqlite3.Binary(domain)])
			conn.commit()
	if len(ip_arr)>2:
		min=5000
		for i in range(len(ip_arr)//2):
			#print(ip_arr[i*2])
			time=avarage_delay(ip_arr[i*2])
			if time<min :
				best_domain=ip_arr[i*2]
				best_ttl=ip_arr[i*2+1]
				min=time
		cursor.execute("UPDATE request_list set best = '"+best_domain+"' where domain=?",[sqlite3.Binary(domain)])
		conn.commit()
		return best_domain,best_ttl
	return ip_arr[0],ip_arr[1]
	
#print(analysis(b"\x03www\x05baidu\x03com"))
#domain=b"\x03map\x05baidu\x03com"
#domain=b"\x04home\x05pjkey\x03com"
#domain=b"\x03www\x01a\x06shifen\x03com"
domain=b"\x03www\x06aliyun\x03com"
#domain=b"\x07jxtest1\x05gtvps\x03xin"
#domain=b"\x04qqhx\x02qq\x03com"
conn = sqlite3.connect('request_data.db')
print(analysis(conn,domain))