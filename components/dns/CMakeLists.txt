idf_component_register(SRCS "dns_server.cpp" "dns_cache.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core blocklist stats lwip
                       PRIV_REQUIRES log esp_hw_support esp_timer)
