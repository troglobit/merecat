FROM alpine:3.6

# Build depends
RUN apk add --no-cache gcc musl-dev make automake autoconf zlib-dev

# Install from GIT
WORKDIR .
ADD . /merecat
RUN cd merecat/; ./build.sh; make install-strip; cd ..; rm -rf merecat

# Alternatively, install from released tarball
#RUN wget http://ftp.troglobit.com/merecat/merecat-2.32.tar.xz; \
#    tar xf merecat-2.32.tar.bz2; \
#    ./build.sh
#    make install-strip

# Clean up container
# m4 perl binutils binutils-libs bmp isl libgomp libatomic pkgconf 
RUN apk del --purge gcc musl-dev make automake autoconf zlib-dev

EXPOSE 80
VOLUME /var/www
ENTRYPOINT merecat -p 80 -n /var/www
