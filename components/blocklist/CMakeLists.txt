idf_component_register(SRCS "blocklist_store.cpp" "domain_list.cpp" "domain_filter.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core esp_partition mbedtls
                       PRIV_REQUIRES log nvs_flash)
