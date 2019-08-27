#ifndef _pcap_h
#define _pcap_h
 
typedef unsigned int  bpf_u_int32;
typedef unsigned short  u_short;
typedef int bpf_int32;
typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

//pacp文件头结构体
struct pcap_file_header
{
 	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;    
	bpf_u_int32 sigfigs;   
	bpf_u_int32 snaplen;   
	bpf_u_int32 linktype;  
};

//时间戳
struct time_val
{
	bpf_u_int32 tv_sec;
	bpf_u_int32 timestamp_ms;
};

//pcap数据包头结构体
struct pcap_pkthdr
{
	struct time_val ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;				 
};
//数据帧头
typedef struct FramHeader_t
{ 
	u_int8 DstMAC[6]; //目的MAC地址	
	u_int8 SrcMAC[6]; //源MAC地址	
	u_short FrameType; //帧类型		
}fram_header_t;
//IP数据报头
typedef struct Ip_Header_t
{
	u_int8 Ver_HLen;       //版本+报头长度
	u_int8 TOS;            //服务类型
	u_int16 TotalLen;       //总长度
	u_int16 ID;            //标识
	u_int16 Flag_Segment;   //标志+片偏移
	u_int8 TTL;            //生存周期
	u_int8 Protocol;       //协议类型
	u_int16 Checksum;       //头部校验和
	u_int32 SrcIP; //源IP地址
	u_int32 DstIP; //目的IP地址
}ip_header_t;
#endif
