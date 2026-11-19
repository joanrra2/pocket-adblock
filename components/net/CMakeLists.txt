idf_component_register(SRCS "wifi_manager.cpp" "lan_dhcp.cpp" "eth_w5500.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core esp_wifi esp_netif esp_event esp_timer
                       PRIV_REQUIRES log esp_hw_support lwip esp_eth esp_driver_spi esp_driver_gpio)

# Count what lwIP's DHCP server receives and answers (LanDhcp diagnostics):
# the documented way to add hooks to the lwip component.
idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
target_compile_options(${lwip_lib} PRIVATE "-I${CMAKE_CURRENT_LIST_DIR}/include")
target_compile_definitions(${lwip_lib} PRIVATE "ESP_IDF_LWIP_HOOK_FILENAME=\"sinkhole/lan_dhcp_hooks.h\"")
