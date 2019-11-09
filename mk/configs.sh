#!/bin/sh

# Try building a clearly arbitrary set of configurations

set -e

makes() {
    gmake clean && nice nice gmake base "$@"
}

# defaults for this system
makes

# flip flop algorithms
makes USE_SERPENT=true USE_TWOFISH=true USE_3DES=true USE_DH2=true USE_DH22=true USE_DH23=true USE_DH24=true USE_DH31=true USE_CAMELLIA=true USE_CAST=true USE_RIPEMD=true
makes USE_SERPENT=false USE_TWOFISH=false USE_3DES=false USE_DH2=false USE_DH22=false USE_DH23=false USE_DH24=false USE_DH31=false USE_CAMELLIA=false USE_CAST=false USE_RIPEMD=false

# flip flop other common flags
makes USE_DNSSEC=true USE_SECCOMP=true
makes USE_DNSSEC=false USE_SECCOMP=false
