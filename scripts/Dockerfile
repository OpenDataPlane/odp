FROM drydockaarch64/u16:v5.10.1

RUN if $(sudo update-alternatives --list gcc); \
      then sudo update-alternatives --remove-all gcc; \
    fi

RUN sudo apt-get update && sudo apt-get install -yy \
  autoconf \
  automake \
  ccache \
  clang-3.8 \
  gcc-4.8 \
  graphviz \
  kmod \
  libconfig-dev \
  libcunit1-dev \
  libnuma-dev \
  libpcap-dev \
  libssl-dev \
  libtool \
  linux-headers-`uname -r` \
  mscgen \
  ruby-dev \
  xsltproc

RUN sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 10
RUN sudo ln -s /usr/bin/clang-3.8 /usr/bin/clang
