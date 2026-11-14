idf_component_register(SRCS "firmware_updater.cpp" "blocklist_updater.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core blocklist net app_update
                       PRIV_REQUIRES log esp_http_client esp_timer esp_app_format mbedtls)
