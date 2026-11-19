idf_component_register(SRCS "app.cpp" "boot_button.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core blocklist dns stats net update web wol led notify
                       PRIV_REQUIRES log esp_event esp_netif esp_timer esp_driver_gpio nvs_flash)
