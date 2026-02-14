# Install script for directory: /home/runner/work/libdatachannel/libdatachannel

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.so.0.24.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.so.0.24"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/libdatachannel.so.0.24.1"
    "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/libdatachannel.so.0.24"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.so.0.24.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.so.0.24"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/libdatachannel.so")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/rtc" TYPE FILE FILES
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/candidate.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/channel.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/configuration.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/datachannel.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/dependencydescriptor.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/description.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/iceudpmuxlistener.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/mediahandler.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtcpreceivingsession.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/common.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/global.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/message.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/frameinfo.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/peerconnection.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/reliability.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtc.h"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtc.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtp.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/track.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/websocket.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/websocketserver.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtppacketizationconfig.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtcpsrreporter.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtppacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtpdepacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/h264rtppacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/h264rtpdepacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/nalunit.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/h265rtppacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/h265rtpdepacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/h265nalunit.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/av1rtppacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/vp8rtppacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/vp8rtpdepacketizer.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rtcpnackresponder.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/utils.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/plihandler.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/pacinghandler.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/rembhandler.hpp"
    "/home/runner/work/libdatachannel/libdatachannel/include/rtc/version.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets.cmake"
         "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/CMakeFiles/Export/32c821eb1e7b36c3a3818aec162f7fd2/LibDataChannelTargets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel" TYPE FILE FILES "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/CMakeFiles/Export/32c821eb1e7b36c3a3818aec162f7fd2/LibDataChannelTargets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel" TYPE FILE FILES "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/CMakeFiles/Export/32c821eb1e7b36c3a3818aec162f7fd2/LibDataChannelTargets-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel" TYPE FILE FILES
    "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/LibDataChannelConfig.cmake"
    "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/LibDataChannelConfigVersion.cmake"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/client/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/client-benchmark/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/media-receiver/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/media-sender/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/media-sfu/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/streamer/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/copy-paste/cmake_install.cmake")
  include("/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/examples/copy-paste-capi/cmake_install.cmake")

endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/runner/work/libdatachannel/libdatachannel/_codeql_build_dir/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
