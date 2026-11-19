// Wired uplink: a WIZnet W5500 module on SPI (CONFIG_SINKHOLE_ETH_W5500).
// Started once at boot; every allocation here happens then and is kept.

#include "sdkconfig.h"

#if CONFIG_SINKHOLE_ETH_W5500

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_eth.h"
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "sinkhole/wifi_manager.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "eth";
constexpr uint32_t kPollMs = 10;  // without an INT pin: how often the chip is checked

// The driver keeps a pointer to this: it must outlive the MAC.
spi_device_interface_config_t gSpiDev{};
}  // namespace

esp_netif_t* startW5500()
{
    const auto host = static_cast<spi_host_device_t>(CONFIG_SINKHOLE_ETH_SPI_HOST);
    if (CONFIG_SINKHOLE_ETH_INT_GPIO >= 0) {
        const esp_err_t isr = gpio_install_isr_service(0);
        if (isr != ESP_OK && isr != ESP_ERR_INVALID_STATE) return nullptr;  // INVALID_STATE: already installed
    }
    spi_bus_config_t bus{};
    bus.miso_io_num = CONFIG_SINKHOLE_ETH_MISO_GPIO;
    bus.mosi_io_num = CONFIG_SINKHOLE_ETH_MOSI_GPIO;
    bus.sclk_io_num = CONFIG_SINKHOLE_ETH_SCLK_GPIO;
    bus.quadwp_io_num = -1;
    bus.quadhd_io_num = -1;
    if (spi_bus_initialize(host, &bus, SPI_DMA_CH_AUTO) != ESP_OK) {
        ESP_LOGE(TAG, "SPI bus init failed: check the W5500 pins");
        return nullptr;
    }
    gSpiDev.mode = 0;
    gSpiDev.clock_speed_hz = CONFIG_SINKHOLE_ETH_SPI_MHZ * 1000 * 1000;
    gSpiDev.queue_size = 16;
    gSpiDev.spics_io_num = CONFIG_SINKHOLE_ETH_CS_GPIO;

    eth_w5500_config_t w5500 = ETH_W5500_DEFAULT_CONFIG(host, &gSpiDev);
    w5500.base.int_gpio_num = CONFIG_SINKHOLE_ETH_INT_GPIO;
    if (CONFIG_SINKHOLE_ETH_INT_GPIO < 0) w5500.base.poll_period_ms = kPollMs;
    eth_mac_config_t macCfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phyCfg = ETH_PHY_DEFAULT_CONFIG();
    phyCfg.reset_gpio_num = CONFIG_SINKHOLE_ETH_RST_GPIO;
    esp_eth_mac_t* mac = esp_eth_mac_new_w5500(&w5500, &macCfg);
    esp_eth_phy_t* phy = esp_eth_phy_new_w5500(&phyCfg);
    if (!mac || !phy) {
        ESP_LOGE(TAG, "W5500 driver could not start");
        return nullptr;
    }
    esp_eth_config_t ethCfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth = nullptr;
    if (esp_eth_driver_install(&ethCfg, &eth) != ESP_OK) {
        ESP_LOGE(TAG, "no W5500 answering on SPI: check the wiring");
        return nullptr;
    }
    // The W5500 has no address of its own: use the chip's Ethernet MAC.
    uint8_t addr[6];
    esp_read_mac(addr, ESP_MAC_ETH);
    esp_eth_ioctl(eth, ETH_CMD_S_MAC_ADDR, addr);

    const esp_netif_config_t netifCfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t* netif = esp_netif_new(&netifCfg);
    if (!netif || esp_netif_attach(netif, esp_eth_new_netif_glue(eth)) != ESP_OK ||
        esp_eth_start(eth) != ESP_OK) {
        ESP_LOGE(TAG, "Ethernet interface could not start");
        return nullptr;
    }
    ESP_LOGI(TAG, "W5500 started, waiting for a cable");
    return netif;
}

}  // namespace sinkhole

#endif
