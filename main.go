package main
import (
	"net"
	"fmt"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"os"
	"bufio"
	"strings"
	"regexp"
	"unsafe"
)
var hostmap map[string]string
// rdns DNS转发函数
// 参数：
// buf 数据包内容
// l 服务端socket
// c 客户端地址
func rdns(buf []byte,l *net.UDPConn,c *net.UDPAddr){
	s,err:=net.Dial("udp4",os.Args[1]+":53")
	if err!=nil{
		fmt.Println(err.Error())
		return
	}
	//设置读超时，主要是防止网络超时等原因导致多客户端请求时出现大量rdns线程堵塞
	s.SetReadDeadline(time.Now().Add(time.Second*5))
	_,err=s.Write(buf)
	if err!=nil{
		return
	}
	readbuf:=make([]byte,65536)
	n,err:=s.Read(readbuf)
	if err==nil{
		//将结果直接发送给客户端
		l.WriteTo(readbuf[:n],c)
	}
	s.Close()
}
func startDNSserver(){
	l,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.ParseIP("0.0.0.0"),Port:53})
	if err!=nil{
		return
	}
	fmt.Println("DNS服务器成功监听在",l.LocalAddr())
	buf:=make([]byte,65536)
	for{
		n,client,err:=l.ReadFromUDP(buf)
		if err!=nil{
			continue
		}
		//调用gopacket解析数据包
		packet:=gopacket.NewPacket(buf[:n],layers.LayerTypeDNS,gopacket.Default)
		packetdecoded:=packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		//如果是正常DNS包而且是请求解析数据包，就测试要请求解析的域名在不在自定义列表
		if packetdecoded!=nil && packetdecoded.QR==false && len(packetdecoded.Questions)>0{
			host:=packetdecoded.Questions[0].Name
			if ip,flag:=testhost(host);flag{
				//在自定义列表则生成一个DNS回复数据包并返回给客户端
				go retDNS(packetdecoded,ip,l,client)
				continue
			}
		}
		//不在自定义列表就中转给远程服务器解析
		go rdns(buf[:n],l,client)
	}
}
//retDNS 生成DNS查询回复数据包
// 参数：
// packet 查询数据包
// ip 解析结果ip
// l 服务端socket
// c 客户端地址
func retDNS(packet *layers.DNS,ip string,l *net.UDPConn,c *net.UDPAddr){
	buffer:=gopacket.NewSerializeBuffer()
	//　具体DNS协议说明可以自行找一些资料来看
	a:=layers.DNS{
		ID:packet.ID,
		QR:true,
		OpCode:0,
		AA:true,
		RD:packet.RD,
		RA:false,
		ResponseCode:0,
		QDCount:1,
		ANCount:1,
		Z:1,
		Questions:packet.Questions,
		Answers:[]layers.DNSResourceRecord{
			layers.DNSResourceRecord{
				Name:packet.Questions[0].Name,
				Type:1,
				Class:1,
				TTL:600,
				IP:net.ParseIP(ip),
			},
		},
	}
	a.SerializeTo(buffer,gopacket.SerializeOptions{})
	l.WriteTo(buffer.Bytes(),c)
}
// loadmap 从host2ip.txt加载自定义列表
func loadmap(){
	hostmap=make(map[string]string)
	fmt.Println("开始加载预置列表，内容如下:")
	defer func(){
		fmt.Println("预置列表显示完毕，一共",len(hostmap),"行")
	}()
	f,err:=os.OpenFile("host2ip.txt",os.O_RDONLY,0666)
	if err!=nil{
		return
	}
	s:=bufio.NewReader(f)
	for{
		linebuf,_,err:=s.ReadLine()
		if err!=nil{
			break
		}
		line:=B2s(linebuf)
		arr:=strings.Split(line," ")
		if len(arr)==2{
			hostmap[arr[0]]=arr[1]
		}
	}
	for k,v:=range hostmap{
		fmt.Printf("%s    %s\n",k,v)
	}
}

// testhost 利用正则表达式判断host是否在自定义列表里面
// 参数：
// host 要解析的域名
func testhost(host []byte)(string,bool){
	hoststr:=B2s(host)
	fmt.Println("用户解析了",hoststr)
	for k,v:=range hostmap{
		if b,_:=regexp.MatchString(k,hoststr);b{
			return v,true
		}
	}
	return "",false
}

// B2s []byte转string
func B2s(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}

func main(){
	if len(os.Args)!=2{
		fmt.Println("usage:",os.Args[0],"8.8.8.8")
		os.Exit(-1)
	}
	loadmap()
	startDNSserver()
}