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
ARG NUCLEI_VERSION=v3.11.1
ARG DALFOX_VERSION=v3.2.3
ARG COMMIX_VERSION=v4.1
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
        unzip \
    && rm -rf /var/lib/apt/lists/*

# gobuster : binaire de release GitHub multi-arch, nom identique au code
# ('gobuster', jamais 'gobuster3' - incident #6, aucun symlink de compatibilite).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) GB_ARCH=x86_64 ;; \
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

# nuclei : binaire de release GitHub multi-arch. Contrairement a gobuster/ffuf,
# l'archive est un .zip (pas .tar.gz) - nommage verifie via l'API GitHub avant
# d'ecrire cette regle (incident #6 : ne jamais supposer qu'un outil suit le
# meme schema qu'un autre). Templates communautaires pre-telecharges a la
# construction pour ne pas en dependre au premier lancement.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) NUCLEI_ARCH=amd64 ;; \
        arm64) NUCLEI_ARCH=arm64 ;; \
        *) echo "architecture non supportee: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    NUCLEI_VER_NUM="${NUCLEI_VERSION#v}"; \
    curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VER_NUM}_linux_${NUCLEI_ARCH}.zip"; \
    unzip -p /tmp/nuclei.zip nuclei > /usr/local/bin/nuclei; \
    chmod +x /usr/local/bin/nuclei; \
    rm -f /tmp/nuclei.zip; \
    nuclei -update-templates -silent || true

# dalfox : binaire de release GitHub multi-arch. Nommage encore different des
# trois autres outils bases sur des binaires Go de ce Dockerfile (gobuster,
# ffuf, nuclei) - verifie individuellement via l'API GitHub, jamais suppose :
# "dalfox-vX.Y.Z-linux-x86_64.tar.gz" (le "v" du tag est conserve dans le nom
# de fichier ici) et "aarch64" plutot que "arm64" pour la variante ARM.
# Piege supplementaire trouve en build reel (pas seulement le nom de
# l'archive, sa structure interne aussi) : contrairement a gobuster/ffuf/
# nuclei qui extraient le binaire a la racine, dalfox l'imbrique dans un
# sous-dossier "dalfox-vX.Y.Z-linux-<arch>/dalfox" - d'ou --strip-components=1
# plutot qu'un nom de fichier fixe dans l'appel tar.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) DALFOX_ARCH=x86_64 ;; \
        arm64) DALFOX_ARCH=aarch64 ;; \
        *) echo "architecture non supportee: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/${DALFOX_VERSION}/dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}.tar.gz"; \
    mkdir -p /tmp/dalfox-extract; \
    tar -xzf /tmp/dalfox.tar.gz -C /tmp/dalfox-extract --strip-components=1; \
    install -m 0755 /tmp/dalfox-extract/dalfox /usr/local/bin/dalfox; \
    rm -rf /tmp/dalfox.tar.gz /tmp/dalfox-extract

# commix : meme probleme que nikto/sqlmap (pas de paquet apt fiable), meme
# correction - clone GitHub + wrapper shell. Reprend directement l'architecture
# de sqlmap (memes auteurs de convention CLI), confirme via son propre code
# source avant ecriture plutot que suppose par analogie.
RUN git clone --branch "${COMMIX_VERSION}" --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && printf '#!/bin/sh\nexec python3 /opt/commix/commix.py "$@"\n' > /usr/local/bin/commix \
    && chmod +x /usr/local/bin/commix

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
