idf_component_register(SRCS "stats.cpp" "device_names.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core
                       PRIV_REQUIRES esp_netif lwip)

# Per-query hot path: optimize for speed (the rest of the image stays -Os).
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
