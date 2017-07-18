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
func rdns(buf []byte,l *net.UDPConn,c *net.UDPAddr){
	s,err:=net.Dial("udp4",os.Args[1]+":53")
	if err!=nil{
		fmt.Println(err.Error())
		return
	}
	s.SetReadDeadline(time.Now().Add(time.Second*5))
	_,err=s.Write(buf)
	if err!=nil{
		return
	}
	readbuf:=make([]byte,65536)
	for{
		n,err:=s.Read(readbuf)
		if err==nil{
			l.WriteTo(readbuf[:n],c)
		}
		s.Close()
		return
	}
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
		packet:=gopacket.NewPacket(buf[:n],layers.LayerTypeDNS,gopacket.Default)
		packetdecoded:=packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		if packetdecoded!=nil && packetdecoded.QR==false && len(packetdecoded.Questions)>0{
			host:=packetdecoded.Questions[0].Name
			if ip,flag:=testhost(host);flag{
				go retDNS(packetdecoded,ip,l,client)
				continue
			}
		}
		go rdns(buf[:n],l,client)
	}
}
func retDNS(packet *layers.DNS,ip string,l *net.UDPConn,c *net.UDPAddr){
	buffer:=gopacket.NewSerializeBuffer()
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