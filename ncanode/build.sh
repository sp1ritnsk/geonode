#!/bin/bash

set -ex

dir="$(dirname $(readlink -f $0))"

cd $dir

container_name="ncanode"
image_name="malikzh/ncanode"

# If not container started
if [ ! "$(docker ps -q -f name=$container_name)" ]; then

    # If container exited
    if [ "$(docker ps -aq -f status=exited -f name=$container_name)" ]; then
        docker rm $container_name
    fi

    # If image not exists
    if [ ! "$(docker images --filter=reference=$image_name -q)" ]; then
        docker build -t malikzh/ncanode .        
    fi

    # Start container
    docker run -ti -d --name ncanode -p 14579:14579 malikzh/ncanode

fi
