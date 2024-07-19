# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

FROM debian:stable

LABEL org.opencontainers.image.authors="stefan.tatschner@aisec.fraunhofer.de"

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y python3 python3-poetry

WORKDIR /app/gallia
COPY . .
RUN ["poetry", "install"]

ENTRYPOINT [ "poetry", "run", "gallia" ]
