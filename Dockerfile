# syntax=docker/dockerfile:1

# Base epinglee (incident #1 : python:3.11-slim sans version Debian a change
# de version majeure sous les pieds du projet, cassant l'installation de
# paquets qui existaient la veille).
FROM python:3.11-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libcairo2-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.11-slim-bookworm AS final

ARG GOBUSTER_VERSION=v3.6.0
ARG FFUF_VERSION=v2.1.0
ARG NIKTO_VERSION=2.5.0
ARG SQLMAP_VERSION=1.8.11
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# nmap (-Pn est impose au niveau code, pas ici) + bind9-dnsutils pour la
# resolution DNS de secours + dependances Perl de nikto (incident #7 :
# "Required module not found: JSON" puis "XML::Writer") + dependances
# WeasyPrint pour le rendu PDF + outils de recuperation des binaires de release.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        bind9-dnsutils \
        perl \
        libnet-ssleay-perl \
        libjson-perl \
        libxml-writer-perl \
        libnet-ip-perl \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        libcairo2 \
        shared-mime-info \
        fonts-dejavu-core \
        git \
        curl \
        wget \
        ca-certificates \
        tar \
    && rm -rf /var/lib/apt/lists/*

# gobuster : binaire de release GitHub multi-arch, nom identique au code
# ('gobuster', jamais 'gobuster3' - incident #6, aucun symlink de compatibilite).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) GB_ARCH=amd64 ;; \
        arm64) GB_ARCH=arm64 ;; \
        *) echo "architecture non supportee: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gobuster.tar.gz \
        "https://github.com/OJ/gobuster/releases/download/${GOBUSTER_VERSION}/gobuster_Linux_${GB_ARCH}.tar.gz"; \
    tar -xzf /tmp/gobuster.tar.gz -C /tmp gobuster; \
    install -m 0755 /tmp/gobuster /usr/local/bin/gobuster; \
    rm -f /tmp/gobuster.tar.gz /tmp/gobuster

# ffuf : binaire de release GitHub multi-arch.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) FF_ARCH=amd64 ;; \
        arm64) FF_ARCH=arm64 ;; \
        *) echo "architecture non supportee: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    FFUF_VER_NUM="${FFUF_VERSION#v}"; \
    curl -fsSL -o /tmp/ffuf.tar.gz \
        "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VER_NUM}_linux_${FF_ARCH}.tar.gz"; \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp ffuf; \
    install -m 0755 /tmp/ffuf /usr/local/bin/ffuf; \
    rm -f /tmp/ffuf.tar.gz /tmp/ffuf

# nikto : pas de paquet apt fiable sur Debian recent (incident #2), clone
# GitHub avec tag epingle + wrapper shell sur le PATH.
RUN git clone --branch "${NIKTO_VERSION}" --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# sqlmap : meme probleme (incident #3), meme correction.
RUN git clone --branch "${SQLMAP_VERSION}" --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# Wordlist verifiee a l'execution par tools/gobuster_tool.py::resolve_wordlist.
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content \
    && curl -fsSL -o /usr/share/seclists/Discovery/Web-Content/common.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# Etape finale : ne copie que le necessaire a l'execution, pas les outils de
# compilation ni requirements-dev.txt.
COPY --from=builder /install /usr/local

WORKDIR /app
COPY core ./core
COPY agents ./agents
COPY tools ./tools
COPY api ./api
COPY templates ./templates
COPY main.py ./main.py

RUN mkdir -p /app/reports /app/db

EXPOSE 8000

CMD ["python", "main.py"]
