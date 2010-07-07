#!/bin/sh

# Version of Nox Release:
VERSION=0.2.0
RELEASEDIR=/home/$USER/release/
TOPSRCDIR=/home/$USER/src/asena/nox/

if test ! -e $RELEASEDIR; then
    mkdir -p $RELEASEDIR 
fi    

if test ! -e $RELEASEDIR/scripts; then
    ln -s  $TOPSRCDIR/src/scripts /home/$USER/release/scripts
fi    

rm -rf $RELEASEDIR/release_html.tar
rm -rf $RELEASEDIR/nox-$VERSION*

# Directory change since git and make rely on cwd
(cd $TOPSRCDIR &&
make clean &&
make dist) &&

cp $TOPSRCDIR/nox-$VERSION.tar.gz $RELEASEDIR &&

# Directory change because decompression is silly
(cd $RELEASEDIR &&
gunzip nox-$VERSION.tar.gz &&
tar -xf nox-$VERSION.tar) &&

gzip $RELEASEDIR/nox-$VERSION.tar &&

# Directory change for performance images
#cd /home/$USER/buildtest/ &&
#/home/$USER/buildtest/builder.py -pa --web-update --performance --src-dir=/home/$USER/nox-$VERSION/ &&

# Directory change for analytics.blip
cd $RELEASEDIR/scripts/ &&
$RELEASEDIR/scripts/stagable.py $RELEASEDIR/nox-$VERSION/doc/manual/build/html $RELEASEDIR/nox-$VERSION/doc/manual/build/html &&

# Directory change to keep prefix directory out
(cd $RELEASEDIR/nox-$VERSION/doc/manual/build/html/ &&
tar -cf release_html.tar . &&
mv release_html.tar ../../../../../
) &&

echo Finished 
