#include <WiFi.h>
#include <Wire.h>

#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"

#include <stdio.h>

#include "BluetoothSerial.h"


int a = 0;
//#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14
#define	WIFI_CHANNEL_MAX		(13)
#define	LED_GPIO_PIN			GPIO_NUM_4
//500 ms
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(500)
//1 minute
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(60000)

// Current wifi channel
int curChannel = 1;
int level = 0;

String maclist[64][3]; 
int listcount = 0;


//Need this object to initialize the bluetooth stack
BluetoothSerial SerialBT;

//static wifi_country_t wifi_country = {.cc="CN", .schan=1, .nchan=13, .policy=WIFI_COUNTRY_POLICY_AUTO};

String KnownMac[10][2] = {  // Put devices you want to be reconized
  {"HPPC","7429AFE7D6A5"},
  {"Will-PC","E894Fffffff3"},
  {"TOMMASO","A09169B83748"},
  {"MARIA ROSARIA","A471744F5EA6"},
  {"NAME","MACADDRESS"},
  {"NAME","MACADDRESS"},
  {"NAME","MACADDRESS"},
  {"NAME","MACADDRESS"}
  
  
};

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

static void wifi_sniffer_set_channel(uint8_t channel);

const wifi_promiscuous_filter_t filt={ //Idk what this does
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};



typedef struct { // or this
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

//Network packet header
typedef struct {
	unsigned frame_ctrl:16;
	unsigned duration_id:16;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

//Network packet
typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

//Callback function
static esp_err_t event_handler(void *ctx, system_event_t *event);
//Change channel function
static void wifi_sniffer_set_channel(uint8_t channel);
//Packet to string function
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
//Callback function
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);


esp_err_t event_handler(void *ctx, system_event_t *event)
{
  //system_event_ap_probe_req_rx_t info_dispositivo;

  if (event->event_id == SYSTEM_EVENT_AP_PROBEREQRECVED)
  {
    //system_event_ap_probe_req_rx_t *list_ap_probereqrecved = (system_event_ap_probe_req_rx_t *) malloc(sizeof(system_event_ap_probe_req_rx_t) *info_dispositivo);
  }
  return ESP_OK;
}

const char *
wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch(type) {
	case WIFI_PKT_MGMT: return "MGMT";
	case WIFI_PKT_DATA: return "DATA";
	default:
	case WIFI_PKT_MISC: return "MISC";
	}
}

void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed

  //Filter all packet types but MGMT
	if (type != WIFI_PKT_MGMT)
		return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
	const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
	const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
		" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
		wifi_sniffer_packet_type2str(type),
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
  
	

}

//===== SETUP =====//
void setup() {

  //Open a serial connection so we can output the result of the program
  Serial.begin(115200);
   // setupOLED();
  //setup
  //nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	//ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );/* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );

  //Set promiscuous mode
  esp_wifi_set_promiscuous(true);
  //esp_wifi_set_promiscuous_filter(&filt); //Filter mac address??
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler); //Register callback function

  gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);
  
  Serial.println("Configuration complete");

  SerialBT.begin("ESP32");
}

//Set channel
void
wifi_sniffer_set_channel(uint8_t channel)
{

	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

//===== LOOP =====//
void loop() {
    gpio_set_level(LED_GPIO_PIN,level^=1);
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    
    wifi_sniffer_set_channel(curChannel); //Change channel
    curChannel = (curChannel % WIFI_CHANNEL_MAX) + 1; //Set next channel
    //Send something over bluetooth connection
    SerialBT.println("Hello World");
    delay(500);
    
}