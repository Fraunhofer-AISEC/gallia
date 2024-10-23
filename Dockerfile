# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

FROM debian:stable

LABEL org.opencontainers.image.authors="stefan.tatschner@aisec.fraunhofer.de"

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y pipx

WORKDIR /app/gallia
COPY . .

ENV PATH="/root/.local/bin:$PATH"
RUN ["pipx", "install", "uv"]
RUN ["uv", "sync"]

ENTRYPOINT [ "uv", "run", "gallia" ]
