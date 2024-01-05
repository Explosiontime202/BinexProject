cmake_minimum_required(VERSION 3.27)
project(project C)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_FLAGS "-Wall -Werror -g -fstack-protector -z noexecstack -z relro -z now -pie -fPIE -Wl,-z,relro,-z,now")

add_executable(vuln vuln.c)
