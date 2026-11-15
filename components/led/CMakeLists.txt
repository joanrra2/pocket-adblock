idf_component_register(SRCS "status_led.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core
                       PRIV_REQUIRES log esp_timer esp_driver_gpio esp_driver_rmt esp_hw_support)
