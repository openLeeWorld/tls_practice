cmake_minimum_required(VERSION 3.11)
project(tls_Test)
# 본 cmake는 windows10 wsl2에서 전부 수행
set(CMAKE_CXX_STANDARD 17)

# GMP 라이브러리 경로 수동 설정
set(INCLUDE_DIR "/usr/include") # GMP, nettle 헤더 파일 경로 (nettle은 nettle/*.h), arpa 동일
set(GMP_LIBRARY_1 "/usr/lib/x86_64-linux-gnu/libgmp.so") # GMP 라이브러리 파일 경로
set(GMP_LIBRARY_2 "/usr/lib/x86_64-linux-gnu/libgmpxx.so") # GMP 라이브러리 파일 경로

# openSSL 
find_package(OpenSSL REQUIRED)

# nettle 라이브러리 경로 수동 설정
set(NETTLE_LIBRARIES "/usr/lib/x86_64-linux-gnu/libnettle.so.7.0")

# jsoncpp 라이브러리 경로 수동 설정
set(JSONCPP_LIBRARIES "/usr/lib/x86_64-linux-gnu/libjsoncpp.so") 

# libpthread 라이브러리 경로 수동 설정
#set(PTHREAD_LIBRARIES "/usr/lib/x86_64-linux-gnu/libpthread.so") 

# pthread 라이브러리 추가
find_package(Threads REQUIRED)

# include source (source에서 소스 추가)
set(INCLUDE_DIR2 "/home/amy/cmake_my_project/source")

# include source (tcpip에서 소스 추가)
set(INCLUDE_DIR3 "/home/amy/cmake_my_project/tcpip")

# include source (tls13에서 소스 추가)
set(INCLUDE_DIR4 "/home/amy/cmake_my_project/tls13")
# Include directories 추가
include_directories(${INCLUDE_DIR} ${INCLUDE_DIR2} ${INCLUDE_DIR3} ${INCLUDE_DIR4})

# Catch2 추가
include(FetchContent)
FetchContent_Declare(
  catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.3.2  # 또는 최신 릴리즈 버전을 사용하세요
)
FetchContent_MakeAvailable(catch2)

# 소스 파일 추가
add_executable(tests source/tls.cpp source/base64.cpp source/RSA.cpp source/AES.cpp 
source/elliptic_curve.cpp source/SHA1.cpp source/mpz_utility.cpp source/option.cpp
source/GCM.cpp source/cert.cpp source/der.cpp source/log.cpp source/ECDSA.cpp
tcpip/tcpip.cpp tcpip/Vrecv.cpp tcpip/Http.cpp tcpip/TlsLayer.cpp tcpip/Client.cpp tcpip/Server.cpp
tls13/tls13.cpp tls13/tls13_client.cpp tls13/https.cpp
)
# test/test_tls13.cpp 
# add_executable(tcpip/tcpip.cpp tcpip/Vrecv.cpp tcpip/Http.cpp tcpip/TlsLayer.cpp tcpip/Client.cpp
# tcpip/Server.cpp)

# Catch2 링크
target_link_libraries(tests PRIVATE ${GMP_LIBRARY_1} ${GMP_LIBRARY_2} ${JSONCPP_LIBRARIES} ${NETTLE_LIBRARIES}
Catch2::Catch2WithMain OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
# ${PTHREAD_LIBRARIES}