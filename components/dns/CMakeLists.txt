idf_component_register(SRCS "dns_server.cpp" "dns_cache.cpp" "perf.cpp" "local_records.cpp" "dot_proxy.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core blocklist stats lwip
                       PRIV_REQUIRES log esp_hw_support esp_timer esp-tls mbedtls)

# Per-query hot path: optimize for speed (the rest of the image stays -Os).
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
