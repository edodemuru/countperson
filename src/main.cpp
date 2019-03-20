using namespace std;
#include <WiFi.h>
#include <Wire.h>

#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"

#include <assert.h>   
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string>

//#include <string.h>

#include "freertos/FreeRTOS.h"//kernel di sistema operativo in real-time usato nei dispositivi embedded
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include <vector>

#include <chrono>
#include <hash_map>
#include <rom/md5_hash.h>
#include "mbedtls/md.h"
#include <time.h>
#include "time.h"
#include <WiFiUdp.h>




using namespace std::chrono;

#define BIT0 (1 << 0)

//Impostazioni per connettersi al server
#define SSID "edoHotspot"
#define PASSPHARSE "pippoinamerica"//ssid e password della rete a cui mi voglio collegare

/*#define SSID "PC-GIUSEPPE 6693"
#define PASSPHARSE "729Zg987"*/

#define MESSAGE "HelloTCPServer"
#define TCPServerIP "192.168.137.1" //ip del server nella rete in questione



//#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14
#define	WIFI_CHANNEL_MAX		(13)
#define	LED_GPIO_PIN			GPIO_NUM_4
//500 ms
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(5000)
//1 minute
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(60000)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(50000)


#define deltagrow 4         //termini per espansione lineare dell'array dinamico.//
#define deltashrink 6      // con condiz. necessaria : delta shrink>deltagrow.

const wifi_promiscuous_filter_t filt={ 
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};



typedef struct { 
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

//Frame control flags
typedef struct {
     unsigned protocol:2;
     unsigned type:2;
     unsigned subtype:4;
     unsigned to_ds:1;
     unsigned from_ds:1;
     unsigned more_frag:1;
     unsigned retry:1;
     unsigned pwr_mgmt:1;
     unsigned more_data:1;
     unsigned wep:1;
     unsigned strict:1;
  } wifi_header_frame_control_t;

//Network packet header (MAC header)
typedef struct {
  wifi_header_frame_control_t frame_ctrl;
	//unsigned duration_id:16;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;


//Network packet
typedef struct {
  //Network packet header (Mac)
	wifi_ieee80211_mac_hdr_t hdr;
  //uint8_t payload [2];
	uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

//Callback function
static esp_err_t event_handler(void *ctx, system_event_t *event);
//Change channel function
static void wifi_sniffer_set_channel(uint8_t channel);
//Packet to string function
//static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
//Callback function
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);


static EventGroupHandle_t wifi_event_group;//variabile che identifica un gruppo di eventi wifi(RTOS)
const int CONNECTED_BIT = BIT0;
static const char *TAG="tcp_client";


// Current wifi channel
int curChannel = 1;
int level = 0;

//Interface wifi
wifi_interface_t ifx;

//Mac esp32
uint8_t macEsp32[6];

//Boolean to identify if esp32 is connecting for the first time to server
boolean firstConnection;

//Data to send to server
vector<char> dataToSend;

/*//Uri server ntp
const char* ntpServer = "time.windows.com";
//Offset seconds
const long  gmtOffset_sec = 3600;
const int   daylightOffset_sec = 3600;*/

//Time set in Esp32
time_t timeEsp;
//Timestamp used by packets
string timestamp;
//Timestamp obtained from server into struct tm to define when the esp32 must start to work
struct tm timeWork = {0};
//Timestamp obtained from server into char array
char tmFromServerChar[19];
//Receipt buffer
char dataReceived[64];

vector<char> packetSniffed;

const char* ntpServer = "time.windows.com";
const long  gmtOffset_sec = 3600;
const int   daylightOffset_sec = 0;

void wifi_connect(){//collega la scheda alla rete wifi specificata
    wifi_config_t cfg = {
      .sta ={SSID,PASSPHARSE}
    };      
    /*wifi_config_t cfg = {
        .sta = {
            .ssid = SSID,
            .password = PASSPHARSE,
        },
    };*/
    ESP_ERROR_CHECK( esp_wifi_disconnect() );//mi disconnetto dalla rete alla quale eventualmente mi ero collegato in precedenza
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &cfg) );//configurazione
    ESP_ERROR_CHECK( esp_wifi_connect() );//mi connetto alla wifi
}



esp_err_t event_handler(void *ctx, system_event_t *event)
{
 switch(event->event_id) {//analizzo l'id relativo all'evento
    case SYSTEM_EVENT_STA_START://l'esp32 si è avviata
        wifi_connect();//collego l'esp32 alla wifi
        break;
    case SYSTEM_EVENT_STA_GOT_IP://l'esp32 ha ricevuto l'IP dall'access point a cui si è connesso
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);//setto il bit in modo da sbloccare i relativi task bloccati (???)
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED://l'esp32 si è disconnesso dall'access point
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);//pulisco i bit
        break;
    default:
        break;
    }
  return ESP_OK;
}

void setTime(struct tm tempTime){
    
    //Convert struct tm to local time
    timeEsp = mktime(&tempTime);
    printf("\nTimestamp della esp32: %d/%d/%d %d:%d:%d\n",
    tempTime.tm_mday,tempTime.tm_mon,tempTime.tm_year,tempTime.tm_hour,tempTime.tm_min,tempTime.tm_sec);
}

/*struct tm dateToTimestampFirstConnection(){
    printf("\nDATA ");
    for(int i=0;i<39;i++){
        printf("%c", tmFromServerChar[i]);
    }
    printf("\n");
    //Time now
    struct tm tm_esp;
    //Time start working
    struct tm tm_work;
    
    //Insert string info into struct tm
    sscanf(tmFromServerChar,"%d/%d/%d %d.%d.%d;%d/%d/%d %d.%d.%d",
    &tm_esp.tm_mday,&tm_esp.tm_mon,&tm_esp.tm_year,&tm_esp.tm_hour,&tm_esp.tm_min,&tm_esp.tm_sec,
    &tm_work.tm_mday,&tm_work.tm_mon,&tm_work.tm_year,&tm_work.tm_hour,&tm_work.tm_min,&tm_work.tm_sec);

    printf("\nTimestamp attuale ottenuto dal server %d/%d/%d %d:%d:%d, Timestamp dopo un minuto: %d/%d/%d %d.%d.%d\n",
    tm_esp.tm_mday,tm_esp.tm_mon,tm_esp.tm_year,tm_esp.tm_hour,tm_esp.tm_min,tm_esp.tm_sec,
    tm_work.tm_mday,tm_work.tm_mon,tm_work.tm_year,tm_work.tm_hour,tm_work.tm_min,tm_work.tm_sec);

    //Convert to time registered by esp 32
    tm_esp.tm_mon--;
    tm_esp.tm_year=tm_esp.tm_year-1900;

    tm_work.tm_mon--;
    tm_work.tm_year=tm_work.tm_year-1900;

    printf("\nTimestamp attuale ottenuto dal server dopo modifica: %d/%d/%d %d:%d:%d\n",tm_esp.tm_mday,tm_esp.tm_mon,tm_esp.tm_year,tm_esp.tm_hour,tm_esp.tm_min,tm_esp.tm_sec);
    printf("\nTimestamp dopo un minuto ottenuto dal server dopo modifica: %d/%d/%d %d:%d:%d\n",tm_work.tm_mday,tm_work.tm_mon,tm_work.tm_year,tm_work.tm_hour,tm_work.tm_min,tm_work.tm_sec);
    setTime(tm_esp);
    return tm_work;
}*/

//Retutn struct tm from timestamp
struct tm dateToTimestamp() {

    //Time when the esp32 must start sniffing
    struct tm tm_work;
    
    //Insert string info into struct tm
    sscanf(tmFromServerChar,"%d/%d/%d %d.%d.%d",&tm_work.tm_mday,&tm_work.tm_mon,&tm_work.tm_year,&tm_work.tm_hour,&tm_work.tm_min,&tm_work.tm_sec);

    printf("\nTimestamp dal server: %d/%d/%d %d:%d:%d\n",tm_work.tm_mday,tm_work.tm_mon,tm_work.tm_year,tm_work.tm_hour,tm_work.tm_min,tm_work.tm_sec);

    //Convert to time registered by esp 32
    tm_work.tm_mon--;
    tm_work.tm_year=tm_work.tm_year-1900;

    printf("\nTimestamp dal server dopo modifica: %d/%d/%d %d:%d:%d\n",tm_work.tm_mday,tm_work.tm_mon,tm_work.tm_year,tm_work.tm_hour,tm_work.tm_min,tm_work.tm_sec);
    return tm_work;
}


void tcp_client(){
    printf("tcp_client task started \n");
    //Socket inizialization
    struct sockaddr_in tcpServerAddr;
    tcpServerAddr.sin_addr.s_addr = inet_addr(TCPServerIP);
    tcpServerAddr.sin_family = AF_INET;
    tcpServerAddr.sin_port = htons( 8888 );//8888 is the port to which we connect
    int s, r;
    //char recv_buf[64];//Reception buffer
    while(1){
        xEventGroupWaitBits(wifi_event_group,CONNECTED_BIT,false,true,100);
        s = socket(AF_INET, SOCK_STREAM, 0);//Socket's creation
        if(s < 0) { //Error in socket function
            ESP_LOGE(TAG, "... Failed to allocate socket.\n");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        printf( "... allocated socket\n");
         if(connect(s, (struct sockaddr *)&tcpServerAddr, sizeof(tcpServerAddr)) != 0) { //Connection to server
            // Code executed in case of error in connect function
            ESP_LOGE(TAG, "... socket connect failed errno=%d \n", errno);
            close(s);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        printf("...connected\n");
        // Pointer to char vector
        char* dataTosendChar = &dataToSend[0];
        //Send data
        if( write(s ,dataTosendChar, dataToSend.size()) < 0)
        {
            ESP_LOGE(TAG, "... Send failed \n");
            close(s);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        printf("... socket send success\n");
        do {
            bzero(dataReceived, sizeof(dataReceived));
            r = read(s, dataReceived, sizeof(dataReceived)-1);

            for(int i = 0; i < r; i++) {
                printf("%c",dataReceived[i]);
                //Save timestamp into array
                tmFromServerChar[i] = dataReceived[i];
            }
        } while(r > 0);
        printf("\n... done reading from socket. Last read return=%d errno=%d\r\n", r, errno);
        close(s);
        printf("Sending complete\n");
         //Convert date received from server into timestamp
         timeWork = dateToTimestamp();

        dataToSend.clear();
        return;
        
    }
}

void insertMacIntoData(){
    char macEsp32Char[18];
    sprintf(macEsp32Char,"%02x:%02x:%02x:%02x:%02x:%02x",macEsp32[0],macEsp32[1],macEsp32[2],macEsp32[3],macEsp32[4],macEsp32[5]);
     for(int i=0;i<17;i++){
        dataToSend.push_back(macEsp32Char[i]);
    }

}

//Function to insert channel number into char vector
void insertChanIntoData(int num){
    if(num<10){
        dataToSend.push_back(num +'0');
        packetSniffed.push_back(num +'0');
    }else{
        dataToSend.push_back('1');
        packetSniffed.push_back('1');
        dataToSend.push_back((num-10)+'0');
        packetSniffed.push_back((num-10)+'0');
    }
    dataToSend.push_back(' ');
    packetSniffed.push_back(' ');
}

//Function to insert rssi value into char vector
void insertRssiIntoData(int rssi){
     if(rssi>-10){
        dataToSend.push_back('-');
        packetSniffed.push_back('-');
        dataToSend.push_back(rssi + '0');
        packetSniffed.push_back(rssi + '0');
    }else if(rssi>-100){
        char intchar[3];
        sprintf(intchar,"%d",rssi);
        dataToSend.push_back(intchar[0]);
        packetSniffed.push_back(intchar[0]);
        dataToSend.push_back(intchar[1]);
        packetSniffed.push_back(intchar[1]);
        dataToSend.push_back(intchar[2]);
        packetSniffed.push_back(intchar[2]);
    } else if(rssi == -100){
        char intchar[4];
        sprintf(intchar,"%d",rssi);
        dataToSend.push_back(intchar[0]);
        dataToSend.push_back(intchar[1]);
        dataToSend.push_back(intchar[2]);
        dataToSend.push_back(intchar[3]);
        packetSniffed.push_back(intchar[0]);
        packetSniffed.push_back(intchar[1]);
        packetSniffed.push_back(intchar[2]);
        packetSniffed.push_back(intchar[3]);

    }
    dataToSend.push_back(' ');
    packetSniffed.push_back(' ');
}

//Function to insert address into char vector
void insertAddrIntoData(uint8_t addr1,uint8_t addr2, uint8_t addr3, uint8_t addr4, uint8_t addr5, uint8_t addr6){
    char addrChar[18];
    sprintf(addrChar,"%02x:%02x:%02x:%02x:%02x:%02x",addr1,addr2, addr3, addr4, addr5, addr6);
    for(int i=0;i<17;i++){
        dataToSend.push_back(addrChar[i]);
        packetSniffed.push_back(addrChar[i]);
    }
    dataToSend.push_back(' ');
    packetSniffed.push_back(' ');
}


void insertTimestampIntoData()
{  
  time_t timer;
  struct tm * timeinfo;
  char timestampCharData[26];
  //Obtain actual timer
  time(&timer);
  //Translate time_t into struct tm
  timeinfo = localtime (&timer);
  printf ("\nTempo registrato dalla scheda: %s\n", asctime(timeinfo));
  printf("\nTimestamp dal server prima del calcolo: %d/%d/%d %d:%d:%d\n",timeWork.tm_mday,timeWork.tm_mon,timeWork.tm_year,timeWork.tm_hour,timeWork.tm_min,timeWork.tm_sec);
  //Calculate diffence in seconds between timestamps
  double seconds = difftime(timer,mktime(&timeWork));
  printf("\nTimestamp: %.1f\n", seconds);

  sprintf(timestampCharData,"%s",asctime(timeinfo));

 

  for(int i=0;i<24;i++){
      
        dataToSend.push_back(timestampCharData[i]);
        packetSniffed.push_back(timestampCharData[i]);
    }

    dataToSend.push_back(' ');
    packetSniffed.push_back(' ');

    
}

void calcHash(){
  packetSniffed.push_back('\0');
  char *payload = &packetSniffed[0];
  byte shaResult[32];
 
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  const size_t payloadLength = strlen(payload);         
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength-1);
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);

  printf("Dati di cui calcolo l'hash\n");
  for(int i= 0; i<strlen(payload); i++){
      printf("%c", payload[i]);
  }
  printf("\n");
 
  Serial.print("Hash: ");
 
  for(int i= 0; i<sizeof(shaResult); i++){
      char str[3];
 
      sprintf(str, "%02x", (int)shaResult[i]);
      dataToSend.push_back(str[0]);
      dataToSend.push_back(str[1]);
      Serial.print(str);
    }
    printf("\n");
    packetSniffed.clear();
}


void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed
  //Filter all packet types but MGMT
	if (type != WIFI_PKT_MGMT)
		return;

  // First layer: type cast the received buffer into our generic SDK structure
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
  // Second layer: define pointer to where the actual 802.11 packet is within the structure
	const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  // Third layer: define pointers to the 802.11 packet header and payload
	const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  // Pointer to the frame control section within the packet header
  const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;

  

  //From now on, only probe request packet
  if(frame_ctrl->subtype != 4)
    return;

    //ssid length (25th byte of payload)
    uint8_t length = ppkt->payload[25];

//Print array and insert it into char vector
if(length!=0){
    printf("SSID=");
    for(uint8_t i = 0; i<length; i++){
      printf("%c",ppkt->payload[i+26]);
      dataToSend.push_back(ppkt->payload[i+26]);
      packetSniffed.push_back(ppkt->payload[i+26]);
    }
    printf(", ");
    }
else{
      printf("SSID=NONE, ");
      string n = "None";
      for(int i=0; i<n.size();i++){
          dataToSend.push_back(n[i]);
          packetSniffed.push_back(n[i]);
      }
    
    }
dataToSend.push_back(' ');
packetSniffed.push_back(' ');

//Print address,rssi and channel
  printf("PACKET TYPE=PROBE, CHAN=%02d, RSSI=%02d,"
		" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
		ppkt->rx_ctrl.channel,
		ppkt->rx_ctrl.rssi,
		/* ADDR1 */
		hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
		hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
		/* ADDR2 */
		hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
		hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
		/* ADDR3 */
		hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
		hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
	);
    //Print timestamp
    //time_t timestamp = getTimestamp();
    //printf(",Timestamp=%.1f\n",timestamp);

    insertChanIntoData(ppkt->rx_ctrl.channel);
    insertRssiIntoData(ppkt->rx_ctrl.rssi);
    insertAddrIntoData(hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
    insertTimestampIntoData();
    calcHash();
    dataToSend.push_back(';');
    dataToSend.push_back('\n');
	

}

//===== SETUP =====//
void setup() {

  //Open a serial connection so we can output the result of the program
  Serial.begin(115200);
  //setup
  //nvs_flash_init();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
   wifi_event_group = xEventGroupCreate();//create new group of events
   esp_log_level_set("wifi", ESP_LOG_NONE); // disable wifi driver logging
  tcpip_adapter_init();
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  //Connection to wifi
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );

  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK( esp_wifi_start() );

  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  //setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 0);
  Serial.print("Connection to server NTP ");
  while(time(nullptr) <= 100000) {
    Serial.print(".");
    delay(100);
  }
  printf("\n");
 

  //Disable promiscuous mode
    /* esp_wifi_set_promiscuous(false);
    //Set configuration for client   
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK( esp_wifi_start() );*/


 /* ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
    
  
  //Set promiscuous mode
  esp_wifi_set_promiscuous(true);*/
 
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler); //Register callback function
  gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);

  //Configure interface
  ifx = WIFI_IF_STA;
  //Obtain mac
  esp_wifi_get_mac(ifx,macEsp32);

  //Config this as first connection to server
  firstConnection = true;

 //init and get the time
  

  
  Serial.println("Configuration complete");


}

//Set channel
void
wifi_sniffer_set_channel(uint8_t channel)
{

	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

//Insert request of connection into dataToSend
void insertConnectionRequest(){
    dataToSend.push_back('R');
}

//Esp32 waits so that every esp32 starts at the same moment
void waitTime(){
  time_t now;
  double seconds;

  time(&now);  /* get current time; same as: now = time(NULL)  */
  //Difference between time sent by server and internal time of esp32
  seconds = difftime(mktime(&timeWork),now);

  printf("Number of seconds to wait : %1.f\n",seconds);
  //Wait some seconds
 // delay(seconds * 1000);

   //reset settings
   esp_wifi_restore();

    //Enable promiscuous mode
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK( esp_wifi_start() );
    esp_wifi_set_promiscuous(true);
}

//Function for first connection
void firstConnectionToServer(){
    //Insert data for first connection
    insertConnectionRequest();
    //Connect to server
    //Disable promiscuous mode
    /* esp_wifi_set_promiscuous(false);
    //Set configuration for client   
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK( esp_wifi_start() );*/

    tcp_client();

    //Renable options for future connections
    insertMacIntoData();
    dataToSend.push_back(';');
    dataToSend.push_back('\n');

     
}

//===== LOOP =====//
void loop() { 
    gpio_set_level(LED_GPIO_PIN,level^=1);
    insertMacIntoData();
    dataToSend.push_back(';');
    dataToSend.push_back('\n');
   

   if(firstConnection){
        firstConnectionToServer();
        firstConnection = false;
        
    }

    waitTime();

    printf("Start listening\n");
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    printf("End listening\n");
     //Disable promiscuous mode
     esp_wifi_set_promiscuous(false);
    //Set configuration for client   
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK( esp_wifi_start() );

    //Activate socket and send data
    tcp_client();
    printf("End communication with server\n");

    //reset settings
    /*esp_wifi_restore();

    //Enable promiscuous mode
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK( esp_wifi_start() );
    esp_wifi_set_promiscuous(true);*/

     
    
    //Change channel
    curChannel = (curChannel % WIFI_CHANNEL_MAX) + 1; //Set next channel
    wifi_sniffer_set_channel(curChannel); //Change channel
    printf("Current channel %d\n",curChannel);

    
    
    
    
}