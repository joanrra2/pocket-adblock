idf_component_register(SRCS "blocklist_store.cpp" "domain_list.cpp" "domain_filter.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core esp_partition mbedtls
                       PRIV_REQUIRES log nvs_flash esp_timer heap)

# Per-query hot path: optimize for speed (the rest of the image stays -Os).
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
