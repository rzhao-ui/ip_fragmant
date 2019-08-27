#include<stdio.h>

#include<string.h>

#include<stdlib.h>

#include<time.h>

#include"pcap.h"

int main()
{	
	struct pcap_file_header *file_header;
	struct pcap_pkthdr *ptk_header;
	ip_header_t *ip_header;
	fram_header_t *fram_header;
	FILE *fp,*output;
    int	pkt_offset,i = 0;
	char buf[10240],my_time[1024];

	file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
	
	ptk_header  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	
	ip_header = (ip_header_t *)malloc(sizeof(ip_header_t));
	
	fram_header = (fram_header_t *)malloc(sizeof(fram_header_t));
	
	memset(buf, 0, sizeof(buf));

	if((fp = fopen("IP3_first.pcap","r")) == NULL)	
	{
		printf("error: can not open pcap file\n");	
	}
	if((output = fopen("output.txt","w+")) == NULL)	
	{
		printf("error: can not open output file\n");	
	}
	pkt_offset = 24; //pcap文件头结构 24个字节
	while(fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包
	{
		i++;
		if(fread(ptk_header, 16, 1, fp) != 1) //读pcap数据包头结构	
		{
			printf("\nread end of pcap file\n");
			break;
		}
		printf("%d %d,ptk_header->caplen,pkt->len");
		pkt_offset += 16 + ptk_header->caplen; //下一个数据包的偏移量

	//	strftime(my_time, sizeof(my_time), "%Y-%m-%d %T", localtime(&(ptk_header->ts.tv_sec))); //获取时间
		
	//	printf("%d: %d\n", i,ptk_header->ts.tv_sec);

	//	fseek(fp, 14, SEEK_CUR); //忽略数据帧头	
		if(fread(fram_header,sizeof(fram_header_t),1,fp) != 1 )
		{
			printf("%d: can not read fram_header\n", i);	
			break;
		}
		printf("目的mac:%06x 源mac:%06x 帧类型：%02x\n",fram_header->DstMAC,fram_header->SrcMAC,fram_header->FrameType);
		//IP数据报头 20字节
		if(fread(ip_header, sizeof(ip_header_t), 1, fp) != 1)			
		{
			printf("%d: can not read ip_header\n", i);	
			break;
		}
		sprintf(buf,"版本+报头长度：%02x 服务类型：%02x 总长度：%04x 标识：%02x 标志+偏移量：%04x 生存周期：%02x 协议类型：%02x 头部校验和：%02x 源ip:%02x 目的ip:%02x\n",ip_header->Ver_HLen,ip_header->TOS,ntohs(ip_header->TotalLen),ip_header->ID,ip_header->Flag_Segment,ip_header->TTL,ip_header->Protocol,ip_header->Checksum,ntohs(ip_header->SrcIP),ip_header->DstIP);
		if(fwrite(buf,strlen(buf),1,output) != 1 )
		{
			printf("output file can not write");
			break;
		}
	}
	fclose(fp);
	fclose(output);

	return 0;
}

