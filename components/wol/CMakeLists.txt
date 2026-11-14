idf_component_register(SRCS "wol_service.cpp" "mqtt_bridge.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core net
                       PRIV_REQUIRES log lwip esp_hw_support mbedtls)
