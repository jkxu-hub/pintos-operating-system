# Autolab - autograding docker image for CSE421/521 pintos

FROM --platform=amd64 ubuntu:18.04
LABEL maintainer="Farshad Ghanei <farshadg@buffalo.edu>"

# prerequisites
RUN apt-get update --fix-missing
RUN apt-get update && apt-get install -y apt-utils
RUN apt-get install -y gcc make build-essential libcunit1-dev libcunit1-doc libcunit1 wget python qemu xorg-dev libncurses5-dev gdb git


###############################################
# configuraion and setup for bochs and pintos #
###############################################
ENV PINTOSDIR /home/pintos
ENV DSTDIR /usr/local
ENV SRCDIR /home/source
RUN mkdir -p $SRCDIR
RUN mkdir -p $PINTOSDIR
RUN mkdir -p $DSTDIR/bin
ENV BXSHARE $DSTDIR/share/bochs
ENV PATH="${DSTDIR}/bin:${PATH}"

# Copies pintos skel from the reposity.  These files will be replaced with user files when the container is run, but if its is removed here, it will not build.
# Something like: docker run --name pintos_container -v %cd%\pintos:/home/pintos/
WORKDIR $SRCDIR/
RUN git clone git://pintos-os.org/pintos-anon && cd pintos-anon && git checkout 9f013d0930202eea99c21083b71098a0df64be0d
RUN mv pintos-anon/* $PINTOSDIR
WORKDIR $SRCDIR/

# RUN wget http://www.oldlinux.org/Linux.old/bochs/Bochs/bochs-2.2.6/bochs-2.2.6.tar.gz
#RUN wget http://web.stanford.edu/class/cs140/projects/pintos/bochs-2.2.6.tar.gz

WORKDIR $PINTOSDIR/src/misc/
RUN ./bochs-2.6.11-build.sh /usr/local

WORKDIR $PINTOSDIR/src/utils/
RUN sed -i "5i GDBMACROS=$PINTOSDIR/src/misc/gdb-macros" $PINTOSDIR/src/utils/pintos-gdb
RUN sed -i "s/$sim = \"bochs\" if \!defined $sim/$sim = \"qemu\" if \!defined $sim/" $PINTOSDIR/src/utils/pintos
RUN make
RUN cp backtrace pintos pintos-gdb pintos-mkdisk Pintos.pm pintos-set-cmdline squish-pty squish-unix $DSTDIR/bin

WORKDIR /

# Uncomment thse lines for local testing only
#RUN mkdir -p $PINTOSDIR/submission
#WORKDIR $PINTOSDIR/src/threads/
#ADD test-autograder /home/submission
#WORKDIR /home/submission
#RUN make



