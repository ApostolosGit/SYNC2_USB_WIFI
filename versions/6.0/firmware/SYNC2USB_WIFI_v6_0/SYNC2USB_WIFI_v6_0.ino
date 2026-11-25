/* AIRCAT500 v6.0 TCP LAB prototype. SYNTHETIC DATA ONLY.
 * No external clock/data inputs, no production radar access, no USB changes to v40.0.
 * Nonblocking socket I/O; one bounded outstanding record; no reboot on connection loss.
 * TCP frame: AC5T, version 5, kind 0=heartbeat 1=BSC 2=gap, len u16,
 * sequence u32, session u32, source_us u64, CRC32 u32, payload. Little endian.
 */
#include <Arduino.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <fcntl.h>
#include <errno.h>
#include <esp_timer.h>
#include <esp_random.h>
static constexpr char SSID[]="SYNC-LAB";
static constexpr char PASSWORD[]="LAB-DEMO-ONLY"; // Public example, not the previous private password.
static constexpr char PIN_LINE[]="AIRCAT_TCP_V5 1234\n";
static constexpr uint16_t PORT=5005;
static int listener=-1, peer=-1;
static bool authenticated=false;
static uint32_t sequence=0, session=0, connects=0, disconnects=0;
static uint32_t lastRx=0,lastProgress=0,lastHeartbeat=0;
static uint64_t nextSource=0;
static uint8_t sector=32, inputLen=0;
static char input[32];
static uint8_t tx[128];
static size_t txLen=0,txPos=0;
static uint32_t stalls=0,partials=0,skipped=0;
static void put16(uint8_t *p,uint16_t n){p[0]=n;p[1]=n>>8;}
static void put32(uint8_t *p,uint32_t n){for(int i=0;i<4;i++)p[i]=n>>(8*i);}
static void put64(uint8_t *p,uint64_t n){for(int i=0;i<8;i++)p[i]=n>>(8*i);}
static uint32_t crc32part(uint32_t crc,const uint8_t *p,size_t n){
  while(n--){crc^=*p++;for(int k=0;k<8;k++)crc=(crc>>1)^((crc&1)?0xEDB88320UL:0);}
  return crc;
}
static uint16_t crc16(const uint8_t *p,size_t n){
  uint16_t c=0;while(n--){c^=*p++;for(int k=0;k<8;k++)c=(c>>1)^((c&1)?0x8408:0);}
  return c;
}
static void closePeer(){
  if(peer>=0){close(peer);peer=-1;++disconnects;}
  authenticated=false;inputLen=0;txLen=txPos=0;
}
static bool nonblock(int fd){int f=fcntl(fd,F_GETFL,0);return f>=0&&fcntl(fd,F_SETFL,f|O_NONBLOCK)==0;}
static bool startServer(){
  listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0)return false;
  int one=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
  sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(PORT);a.sin_addr.s_addr=htonl(INADDR_ANY);
  if(!nonblock(listener)||bind(listener,(sockaddr*)&a,sizeof(a))<0||listen(listener,1)<0){
    close(listener);listener=-1;return false;
  }
  return true;
}
static void record(uint8_t kind,uint64_t source,const uint8_t *p,size_t n){
  if(txLen||n>sizeof(tx)-28)return;
  memcpy(tx,"AC5T",4);tx[4]=5;tx[5]=kind;put16(tx+6,n);
  put32(tx+8,sequence++);put32(tx+12,session);put64(tx+16,source);
  if(n)memcpy(tx+28,p,n);
  uint32_t c=crc32part(0xffffffff,tx,24);
  c=crc32part(c,tx+28,n)^0xffffffff;put32(tx+24,c);
  txPos=0;txLen=28+n;lastProgress=millis();
}
static size_t syntheticBsc(uint8_t s,uint8_t *out){
  uint8_t body[9]={uint8_t(s==32?0x19:0x0c),0x40,0x10,0x02,0xfd,0,0,0,0x03};
  body[5]=s==32?0:s;
  size_t inner=s==32?4:2;size_t bodyN=4+inner;
  body[bodyN]=3;uint16_t c=crc16(body,bodyN+1);
  size_t n=0;out[n++]=0x32;out[n++]=0x32;out[n++]=0x32;out[n++]=1;
  for(size_t i=0;i<bodyN;i++){out[n++]=body[i];if(i>=4&&body[i]==0x10)out[n++]=0x10;}
  out[n++]=0x10;out[n++]=3;out[n++]=c;out[n++]=c>>8;return n;
}
static void service(uint32_t now){
  if(listener<0)return;
  if(peer<0){
    int fd=accept(listener,nullptr,nullptr);if(fd<0)return;
    if(!nonblock(fd)){close(fd);return;}
    peer=fd;lastRx=now;authenticated=false;inputLen=0;
  }
  char b[32];int n=recv(peer,b,sizeof(b),0);
  if(n==0){closePeer();return;}
  if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){closePeer();return;}
  for(int i=0;i<n;i++){
    if(inputLen>=sizeof(input)-1){closePeer();return;}
    input[inputLen++]=b[i];
    if(b[i]=='\n'){
      input[inputLen]=0;
      if(!authenticated&&strcmp(input,PIN_LINE)==0){
        authenticated=true;++connects;session=esp_random();sequence=0;sector=32;
        nextSource=esp_timer_get_time();lastHeartbeat=now;lastRx=now;
        record(0,nextSource,nullptr,0);
      }else if(authenticated&&strcmp(input,"P\n")==0){lastRx=now;}
      else{closePeer();return;}
      inputLen=0;
    }
  }
  if(now-lastRx>10000){closePeer();return;}
  if(!authenticated)return;
  if(txLen){
    int sent=send(peer,tx+txPos,txLen-txPos,0);
    if(sent>0){txPos+=sent;lastProgress=now;if(txPos==txLen){txPos=txLen=0;}else ++partials;}
    else if(sent<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){closePeer();return;}
    else ++stalls;
    if(txLen&&now-lastProgress>10000){closePeer();return;}
    if(txLen)return;
  }
  uint64_t t=esp_timer_get_time();
  // Do not invent elapsed source data after a sender stall: announce a gap.
  if(t>nextSource+500000){
    ++skipped;record(2,t,nullptr,0);sector=32;nextSource=t;return;
  }
  if(t>=nextSource){
    uint8_t frame[32];size_t size=syntheticBsc(sector,frame);
    record(1,nextSource,frame,size);
    sector=(sector==32?0:sector==31?32:sector+1);
    nextSource+=125000;return;
  }
  if(now-lastHeartbeat>=1000){lastHeartbeat=now;record(0,t,nullptr,0);}
}
void setup(){
  Serial.begin(115200);WiFi.mode(WIFI_AP);
  if(!WiFi.softAP(SSID,PASSWORD,6,0,1)||!startServer())Serial.println("LAB TCP startup failed");
  else Serial.println("AIRCAT500 v6.0 LAB synthetic TCP");
}
void loop(){
  service(millis()); // All socket operations nonblocking; no wait for a receiver.
  static uint32_t prev=0;
  if(millis()-prev>=5000){prev=millis();
    if(Serial.availableForWrite()>=96)
      Serial.printf("LAB tcp connects=%lu disconnects=%lu stalls=%lu partials=%lu gaps=%lu\n",
       (unsigned long)connects,(unsigned long)disconnects,(unsigned long)stalls,
       (unsigned long)partials,(unsigned long)skipped);
  }
  delay(1);
}
