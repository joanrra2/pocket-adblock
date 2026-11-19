# Phone notifications (ntfy / Telegram): Pro builds only (CONFIG_SINKHOLE_NOTIFY).
# The header is always there so other components can name the class.
set(srcs "")
if(CONFIG_SINKHOLE_NOTIFY)
    list(APPEND srcs "notifier.cpp")
endif()
idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS "include"
                       REQUIRES core net freertos
                       PRIV_REQUIRES log esp_http_client mbedtls esp_timer heap)
