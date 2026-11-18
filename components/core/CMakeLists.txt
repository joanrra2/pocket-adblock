idf_component_register(SRCS "config.cpp" "boot_log.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES freertos nvs_flash esp_common heap
                       PRIV_REQUIRES log lwip mbedtls esp_hw_support esp_timer esp_netif esp_system)
