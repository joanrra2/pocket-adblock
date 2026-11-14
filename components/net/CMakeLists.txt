idf_component_register(SRCS "wifi_manager.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core esp_wifi esp_netif esp_event esp_timer
                       PRIV_REQUIRES log esp_hw_support)
