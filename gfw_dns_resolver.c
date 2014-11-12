
/**
 * This is a tool used to prevent GFW DNS poisoning and return to the correct ip
 * @author chengkai
 * mail chengkai.me@gmail.com
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>    //you know what this is for
#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <netdb.h>

#define DNS_SERVER  "8.8.8.8"

#ifndef   NI_MAXHOST
#define   NI_MAXHOST 256
#endif

int max_wait_times = 3;
const char black_list[][16] = {
     "74.125.127.102", "74.125.155.102", "74.125.39.102", "74.125.39.113",
     "189.163.17.5", "209.85.229.138", "249.129.46.48","77.4.7.92",
     "128.121.126.139", "159.106.121.75", "169.132.13.103", "192.67.198.6",
     "202.106.1.2", "202.181.7.85", "203.161.230.171", "203.98.7.65",
     "207.12.88.98", "208.56.31.43", "209.145.54.50", "209.220.30.174",
     "209.36.73.33", "211.94.66.147", "213.169.251.35", "216.221.188.182",
     "216.234.179.13", "243.185.187.39", "37.61.54.158", "4.36.66.178",
     "46.82.174.68", "59.24.3.173", "64.33.88.161", "64.33.99.47",
     "64.66.163.251", "65.104.202.252", "65.160.219.113", "66.45.252.237",
     "72.14.205.104", "72.14.205.99", "78.16.49.15", "8.7.198.45", "93.46.8.89",
     "253.157.14.165","180.168.41.175","49.2.123.56",
};

void  gfw_resolve(const char * hostname,char * out_ip) ;
void hexDump (char *desc, void *addr, int len); //hex buff dump for debug
char * build_request_data(char * hostname, int * ret_size) ;
void decode_dns_response(char * buffer, const char * hostna,char * ip) ;
short decode2short(char * buffer) ;
void get_host_name(const char * domain,char * out);



int main(int argc, char const *argv[])
{

     if(argc < 2) {
          printf("Usage: %s domain\n",argv[0]);
     } else {
          while (--argc > 0) {
               char ip[NI_MAXHOST];
               gfw_resolve(*++argv, ip);
               printf ("The real ip is: %s\n", ip);
          }
     }

     /* code */
     return 0;
}

int is_little_endian( )
{
     {
          union w
          {
               int a;
               char b;
          } c;
          c.a = 1;
          return(c.b ==1);
     }
}


void get_host_name(const char * domain, char * out)
{

     struct sockaddr_in sa;
     struct addrinfo *result;

     sa.sin_family = AF_INET;
     int error;

     error = getaddrinfo(domain, NULL, NULL, &result);
     if(error != 0) {
          printf ("no such host %s.\ngetaddrinfo error: %s\n", domain,
                  gai_strerror(error));
          exit(-1);
     }

     memcpy(&sa, result->ai_addr, sizeof(sa));

     error = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                         out, NI_MAXHOST, NULL, 0, 0);

     if(error != 0) {
          printf("getnameinfo error:%d", error);
          exit(-1);
     }

     freeaddrinfo(result);

}

int is_bad_ip(char * ip)
{
     int i ;
     for(i = 0; i < sizeof(black_list) / sizeof black_list[0]; i++) {
          if(strcmp(black_list[i], ip) == 0) {
               // printf(">>>>> got bad ip:%s",ip);
#ifdef DEBUG
               printf(">>>>> got bad ip:%s", ip);
#endif
               bzero(ip, NI_MAXHOST);
               return 1;
          }
     }
     return 0;
}

//extract ip address from dns answer package
void decode_dns_response(char * buffer,const char * hostna,char * ip)
{
     int h_len = strlen(hostna);
     char * p = buffer + 6; //skip qncount
     short qncount = decode2short(p);

     //skip query answer field
     p = buffer  + 1+ 12 +  h_len + 1  + 4;

     int i;
     for(i = 0; i < qncount; i++) {
          char flag = p[0];
          if((flag & 0xc0) == 0xc0) {
               p+= 2;
          }
          else {
               p+= 1+ h_len + 1;
          }
          short query_type =  decode2short(p);


#ifdef DEBUG
          printf("qncount = %d query type:%d \n", qncount, query_type);
#endif


          p += 8;
          int data_len = decode2short(p);

          p += 2; //move to data area

          if(query_type == 0x0001) {
               bzero(ip,NI_MAXHOST);
               int j;
               for(j = 0; j < data_len; j ++) {

                    int v  = p[0];
                    v = v>0?v:0x0ff & v;
                    char tmp[4];
                    sprintf(tmp, "%d", v);
                    strcat(ip, tmp);
                    if(j < data_len - 1) {
                         strcat(ip, ".");
                    }
                    p++;
               }

          } else {
               p += data_len;
          }

     }
}

short decode2short(char * buffer) {
     short v = 0;
     int i = 0; //index
     char * p = (char *) &v;

     if(is_little_endian) {
          p[i] = buffer[i+1];
          p[i+1] = buffer[i];
     } else {
          p[i] = buffer[i];
          p[i+1] = buffer[i+1];
     }
     return v;
}

void  gfw_resolve(const char * hostname, char * out_ip)
{
     struct sockaddr_in a;
     struct sockaddr_in dest;

     int s;

     get_host_name(hostname, out_ip);

     if(!is_bad_ip(out_ip)) {
          return;
     }

     s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

     dest.sin_family = AF_INET;
     dest.sin_port = htons(53);
     dest.sin_addr.s_addr = inet_addr(DNS_SERVER);

     socklen_t addr_len =sizeof(struct sockaddr_in);

     char buff[]  = {0x20, 0x30, 0x40, 0x50};

     char host_buf[strlen(hostname)];
     strcpy(host_buf, hostname);

     int len;

     char * buffer =  build_request_data(host_buf,&len);

     if(sendto(s,(char*)buffer, len,0,(struct sockaddr*)&dest, addr_len) < 0) {
          perror("sendto failed");
     }

#ifdef DEBUG
     printf ("================= send request to from dns server  ================\n");
     printf("buffer len %d\n", len);
     hexDump("send buffer", buffer, len);
#endif


     int i ;
     for (i = 0; i < max_wait_times; i++) {
          char recv_buf[1024];

          len = recvfrom(s, recv_buf, sizeof(recv_buf),0, (struct sockaddr*)&dest,&addr_len);

#ifdef DEBUG
          printf ("================= receive from dns server  ================\n");
          printf("receive len %d\n", len);
          hexDump("receive buffer", recv_buf,len);
#endif

          decode_dns_response(recv_buf, hostname,out_ip);

          if(!is_bad_ip(out_ip)) {
               break;
          }

     }

     free(buffer);
}

char * build_request_data(char * hostname,int * ret_size)
{
     //head + (host length +1) + eof sign + qtype + qclass
     int size = 12 + strlen(hostname) + 1 + 1+ 4;
     char * buffer = (char *) malloc (size);
     char * pbuf = buffer;

     bzero(buffer, size);

     unsigned short seq = rand();

     char header[] = {0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
     memcpy(pbuf, &seq, 2);
     pbuf += 2;
     memcpy(pbuf, header, 10);
     pbuf += 10;
     char * pstr = strtok(hostname, ".");
     while(pstr != NULL)
     {

          char len = strlen(pstr);
          memcpy(pbuf, &len, 1);
          // strncpy(buffer, &len, 1);
          pbuf+=1;
          memcpy(pbuf, pstr, len);
          pstr = strtok(NULL, ".");
          pbuf += len;
     }

     pbuf += 1; //eof of domain

     char extra_data[] = {0x00, 0x01, 0x00, 0x01};

     memcpy(pbuf, extra_data, 4);
     //return the buffer size to caller
     *ret_size = size;
     return buffer;
}

//for debug
void hexDump (char *desc, void *addr, int len) {
     int i;
     unsigned char buff[17];
     unsigned char *pc = (unsigned char*)addr;

     // Output description if given.
     if (desc != NULL)
          printf ("%s:\n", desc);
     // Process every byte in the data.
     for (i = 0; i < len; i++) {
          // Multiple of 16 means new line (with line offset).

          if ((i % 16) == 0) {
               // Just don't print ASCII for the zeroth line.
               if (i != 0)
                    printf ("  %s\n", buff);
               // Output the offset.
               printf ("  %04x ", i);
          }

          // Now the hex code for the specific character.
          printf (" %02x", pc[i]);

          // And store a printable ASCII character for later.
          if ((pc[i] < 0x20) || (pc[i] > 0x7e))
               buff[i % 16] = '.';
          else
               buff[i % 16] = pc[i];
          buff[(i % 16) + 1] = '\0';
     }

     // Pad out last line if not exactly 16 characters.
     while ((i % 16) != 0) {
          printf ("   ");
          i++;
     }

     // And print the final ASCII bit.
     printf ("  %s\n", buff);
}
