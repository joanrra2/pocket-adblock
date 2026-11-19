idf_component_register(SRCS "config.cpp" "boot_log.cpp" "log_buffer.cpp" "events.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES freertos nvs_flash esp_common heap esp_timer
                       PRIV_REQUIRES log lwip mbedtls esp_hw_support esp_netif esp_system)
