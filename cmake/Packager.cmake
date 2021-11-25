# Copyright (c) 2017-2019 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#############
# RPM/DEB/TGZ Packaging utils
#

set(CONTACT "ivan.shvedunov@travelping.com" CACHE STRING "Contact")
set(PACKAGE_MAINTAINER "UPG Team" CACHE STRING "Maintainer")
set(PACKAGE_VENDOR "Travelping GmbH" CACHE STRING "Vendor")

# macro(set)

macro(make_packages)
  if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    # parse /etc/os-release
    file(READ "/etc/os-release" os_version)
    string(REPLACE "\n" ";" os_version ${os_version})
    foreach(_ver ${os_version})
      string(REPLACE "=" ";" _ver ${_ver})
      list(GET _ver 0 _name)
      list(GET _ver 1 _value)
      set(OS_${_name} ${_value})
    endforeach()

    #extract version from git
    execute_process(
      COMMAND git describe --long --tags
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
      OUTPUT_VARIABLE VER
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT VER)
      set(VER "v1.0")
    endif()

    string(REGEX REPLACE "v(.*)-([0-9]+)-(g[0-9a-f]+)" "\\1;\\2;\\3" VER ${VER})
    list(GET VER 0 tag)
    string(REPLACE "-" "~" tag ${tag})
    list(GET VER 1 commit_num)
    list(GET VER 2 commit_name)

    message("${tag}")

    if (NOT DEFINED ENV{BUILD_NUMBER})
      set(bld "b1")
    else()
      set(bld "b$ENV{BUILD_NUMBER}")
    endif()

    message("Build number is: ${bld}")

    #define DEB and RPM version numbers
    if(${commit_num} EQUAL 0)
      set(deb_ver "${tag}")
      set(rpm_ver "${tag}")
    else()
      set(deb_ver "${tag}-${commit_num}-${commit_name}")
      set(rpm_ver "${tag}-${commit_num}-${commit_name}")
    endif()

    get_cmake_property(components COMPONENTS)

    if(OS_ID_LIKE MATCHES "debian")
      set(CPACK_GENERATOR "DEB")
      set(type "DEBIAN")

      execute_process(
        COMMAND dpkg --print-architecture
        OUTPUT_VARIABLE arch
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      set(CPACK_PACKAGE_VERSION "${deb_ver}")
      foreach(lc ${components})
        if (${lc} MATCHES ".*Unspecified.*")
          continue()
        endif()

        string(TOUPPER ${lc} uc)
        set(CPACK_${type}_${uc}_FILE_NAME "${lc}_${deb_ver}_${arch}.deb")

        set(DEB_DEPS)
        if (NOT ${${lc}_DEB_DEPENDENCIES} STREQUAL "")
          string(REPLACE "stable_version" ${tag} DEB_DEPS ${${lc}_DEB_DEPENDENCIES})
        endif()

        set(CPACK_${type}_${uc}_PACKAGE_DEPENDS "${DEB_DEPS}")
        set(CPACK_${type}_${uc}_PACKAGE_NAME "${lc}")
        set(CPACK_COMPONENT_${uc}_DESCRIPTION "${${lc}_DESCRIPTION}")
      endforeach()
    elseif(OS_ID_LIKE MATCHES "rhel")
      set(CPACK_GENERATOR "RPM")
      set(type "RPM")

      execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE arch
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      set(CPACK_PACKAGE_VERSION "${rpm_ver}")
      foreach(lc ${components})
        if (${lc} MATCHES ".*Unspecified.*")
          continue()
        endif()

        string(TOUPPER ${lc} uc)
        set(CPACK_${type}_${uc}_DESCRIPTION "${${lc}_DESCRIPTION}")

        set(RPM_DEPS)
        if (NOT ${${lc}_DEB_DEPENDENCIES} STREQUAL "")
          string(REPLACE "stable_version" ${tag} RPM_DEPS ${${lc}_RPM_DEPENDENCIES})
        endif()

        set(CPACK_${type}_${uc}_PACKAGE_REQUIRES "${RPM_DEPS}")

        if(${lc} MATCHES ".*-dev")
          set(package_name ${lc}el)
        else()
          set(package_name ${lc})
        endif()

        set(CPACK_RPM_${uc}_PACKAGE_NAME "${package_name}")
        set(CPACK_${type}_${uc}_FILE_NAME "${package_name}-${rpm_ver}.${arch}.rpm")
      endforeach()
    endif()

    if(CPACK_GENERATOR)
      set(CPACK_PACKAGE_NAME ${ARG_NAME})
      set(CPACK_STRIP_FILES OFF)
      set(CPACK_PACKAGE_VENDOR "${PACKAGE_VENDOR}")
      set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
      set(CPACK_${CPACK_GENERATOR}_COMPONENT_INSTALL ON)
      set(CPACK_${type}_PACKAGE_MAINTAINER "UPG Team")
      set(CPACK_${type}_PACKAGE_RELEASE 1)
      include(CPack)
    endif()
  endif()
endmacro()
