FROM alpine:3.21

# Build depends
RUN apk add --no-cache gcc musl-dev make automake autoconf zlib-dev
# For OpenSSL and libconfuse support:
# RUN apk add --no-cache openssl-dev confuse-dev

# Install from GIT
ADD . /merecat
RUN cd merecat && ./build.sh && make install-strip && cd .. && rm -rf merecat

# Alternatively, install from released tarball
#RUN wget https://ftp.troglobit.com/merecat/merecat-2.32.tar.xz;	\
#    tar xf merecat-2.32.tar.bz2;					\
#    cd merecat-2.32/;							\
#    ./build.sh;							\
#    make install-strip

# Clean up container
# m4 perl binutils binutils-libs bmp isl libgomp libatomic pkgconf
RUN apk del --purge gcc musl-dev make automake autoconf zlib-dev

EXPOSE 80
VOLUME /var/www
ENTRYPOINT ["/usr/sbin/merecat", "-p", "80", "-n", "/var/www"]
