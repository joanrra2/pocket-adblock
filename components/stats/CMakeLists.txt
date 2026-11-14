idf_component_register(SRCS "stats.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core
                       PRIV_REQUIRES esp_netif lwip)
