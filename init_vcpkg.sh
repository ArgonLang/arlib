#! /bin/bash

if [ ! -d "vcpkg" ]; then
    git clone https://www.github.com/microsoft/vcpkg

    if [ $? -ne 0 ]; then
        exit $?
    fi

    echo ""
    echo "VCPKG bootstrap"
    echo ""

    ./vcpkg/bootstrap-vcpkg.sh
    if [ $? -ne 0 ]; then
        exit $?
    fi
else
    echo "VCPKG already exists, skip the installation step"
fi

echo ""
echo "Installing dependencies"
echo ""

./vcpkg/vcpkg install
if [ $? -ne 0 ]; then
    exit $?
fi

echo "Remember to use the toolchain file with CMAKE:"
echo "-DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake"
