project(sniffer C)
add_executable(sniffer sniffer/main.c)
target_link_libraries(sniffer pthread)

project(sniffer_cli C)
add_executable(sniffer_cli cli/main.c)

install(TARGETS sniffer_cli DESTINATION bin)
install(TARGETS sniffer DESTINATION bin)

install(PROGRAMS sniffer.sh DESTINATION /etc/init.d/ RENAME sniffer) # For SysVinit systems
install(FILES sniffer.service DESTINATION /etc/systemd/system/) # For systemd systems