#!/bin/bash

# Version file generator for software projects.
# Based on GIT_VERSION_GEN,
# extended by Andreas Mull, 2024.

VERSION_GENERATOR=$0
VERSION_FILE=.generated_version
VERSION_DEFAULT=default

function usage
{
    cat << EOT >&2
usage: ${0##*/} [files]

Version file generator for software projects. Based on GIT_VERSION_GEN.

Uses GIT to derive version information and writes it to arbitrary files.
All such files and the special cache file ${VERSION_FILE} should
be added to the .gitignore list.
EOT
    exit $1
}

##
## Template functions for emitting language specific version files
## All functions are called as follows:
## <function> <VERSION> <DIRECTORY> <FILENAME>
## Version is VC from GIT_VERSION_GEN script.
## Directory is the directory of the file to be generated with any
## language typical source folder prefixes removed.
## Filename is the full filename part for the file.
##

# Generate a Java class file:
function java_class
{
    local VERSION=$1
    local DIRECTORY=$2
    local FILENAME=$3

    # Strip source folder and replace slashes with dots:
    PACKAGE=$(echo ${DIRECTORY} | tr '/' '.')

    # Remove filename extension:
    CLASSNAME=${FILENAME%.java}

    # Emit file:
    cat << EOT
/* Generated by ${VERSION_GENERATOR}. Do not edit. */

package ${PACKAGE};

public class ${CLASSNAME}
{
    public static final String GIT_VERSION = "${VERSION}";
}
EOT
}

# Generate a C header file:
function c_header
{
    local VERSION=$1

    cat << EOT
/* Generated by ${VERSION_GENERATOR}. Do not edit. */

#ifndef GIT_VERSION
#define GIT_VERSION "${VERSION}"
#endif
EOT
}

# Generate a TCL include file:
function tcl_include
{
    local VERSION=$1
    
    cat << EOT
// Generated by ${VERSION_GENERATOR}. Do not edit.

set GIT_VERSION "${VERSION}"
EOT
}

# Generate a Makefile environment file:
function make_env
{
    local VERSION=$1

    #local VERSION="1.2"
    #local VERSION="1.2d78"
    #local VERSION="1.2rc56"
    #local VERSION="1.2p34"
    #local VERSION="1.2p34rc56"
    #local VERSION="1.2-5-g3434"
    #local VERSION="1.2-5-g3434-dirty"
    #local VERSION="12.7p5rc8-5-23424234-dirty"
    #local VERSION="999.999p999"
    #local VERSION="1.1p9999"           # MUST FAIL
    #local VERSION="1.9999p9999"        # MUST FAIL
    #local VERSION="9999.9999p9999"     # MUST FAIL

    # Major and minor version are always required
    VER_MAJOR=$(echo ${VERSION} | cut -d '.' -f 1)
    VER_MINOR=$(echo ${VERSION} \
        | cut -d '.' -f 2 | cut -d 'p' -f 1 \
        | cut -d 'r' -f 1 | cut -d 'd' -f 1 \
        | cut -d '-' -f 1)

    # Check for optional patch version
    VER_PATCH="0"
    if [[ "${VERSION}" == *"p"* ]]; then
        VER_PATCH=$(echo ${VERSION} \
            | cut -d '.' -f 2 | cut -d 'p' -f 2 \
            | cut -d 'r' -f 1 | cut -d 'd' -f 1 \
            | cut -d '-' -f 1)
    fi

    # Check major, minor and patch version for valid values
    if [ -z ${VER_MAJOR} ]; then
        echo "ERROR: empty major number"
        exit 1;
    fi

    if [ -z ${VER_MINOR} ]; then
        echo "ERROR: empty minor number"
        exit 1;
    fi

    if [ ${VER_MAJOR} -gt 999 ] || [ ${VER_MAJOR} -lt 1 ]; then
        echo "ERROR: invalid major number: ${VER_MAJOR}"
        exit 1
    fi

    if [ ${VER_MINOR} -gt 999 ] || [ ${VER_MINOR} -lt 0 ]; then
        echo "ERROR: invalid minor number: ${VER_MINOR}"
        exit 1
    fi

    if [ ${VER_PATCH} -gt 999 ] || [ ${VER_PATCH} -lt 0 ]; then
        echo "ERROR: invalid patch number: ${VER_PATCH}"
        exit 1
    fi

    # Pad leading zeros for minor and patch version
    VER_MINOR_PAD=$(printf "%03d" ${VER_MINOR})
    VER_PATCH_PAD=$(printf "%03d" ${VER_PATCH})

    cat << EOT
# Generated by ${VERSION_GENERATOR}. Do not edit.

export CFG_TA_VERSION=${VER_MAJOR}${VER_MINOR_PAD}${VER_PATCH_PAD}
EOT
}

##
## The following part of code is based on
## https://github.com/git/git/blob/master/GIT-VERSION-GEN
##

LINE_FEED='
'

# First see if there is a version file
# (included in release tarballs or a local override by the developer):
if [ -f version ]; then
    VC=$(cat version) || VC="$VERSION_DEFAULT"

# Then try git-describe to determine current version:
elif [ -d ${GIT_DIR:-.git} -o -f .git ]; then
    DESCRIPTION=$(git describe --match "er[0-9]*" --abbrev=7 HEAD 2>/dev/null)
    # According to git-describe(1) the output format is as follows:
    # <tag>-<commitCount>-<abbrevDesc>
    #   commitCount: number of commits since tag
    #   abbrevDesc: object description with prefix "g"
    # i.e.: v1.0.4-14-g2414721
    if [ $? = 0 ]; then
        case "$DESCRIPTION" in
            *$LINE_FEED*)
                VC="$VERSION_DEFAULT"
                ;;
            "")
                VC="none"
                ;;
            er[0-9]*)
                VC="${DESCRIPTION#er}"
                ;;
        esac

        # Check for locally modified files:
        # 1. such ones added to the index
        # 2. such ones not added yet:
        git update-index -q --refresh
        if [ -n "$(git diff-index --name-only HEAD --)" ]; then
            VC="$VC-dirty"
        elif [ -n "$(git status -s)" ]; then
            VC="$VC-unstaged"
        fi
    else
    	VC="$VERSION_DEFAULT"
    fi

# Otherwise use a default:
else
    VC="$VERSION_DEFAULT"
fi

##
## End of code from GIT_VERSION_GEN
##

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage 1
fi

echo "Version: $VC" >&2

# Read the latest generated version from a file to see if it is up-to-date:
if [ -r $VERSION_FILE ]; then
    VF=$(sed -e 's/^GIT_VERSION = //' < $VERSION_FILE)
else
    VF=unset
fi

# Compare both versions
# - if they differ overwrite all files in the argument list
# - if a filename was provided, run this too
if [ "$VC" != "$VF" ] || [ "$1" != "" ]; then
    for FILENAME_WITH_FULL_PATH in $@; do
        # Extract file name part:
        FILE=${FILENAME_WITH_FULL_PATH##*/}

        # Chop off pwd and filename:
        DIR=${FILENAME_WITH_FULL_PATH#$PWD/}
        DIR=${DIR%$FILE}
        DIR=${DIR%/}

        # Take care of files on top-level:
        if [ -z "$DIR" ]; then
            DIR=.
        fi
        
        # Evaluate which sort of language the version file should be:
        FUNC=
        case $FILE in
            *.java)
                FUNC=java_class
                PREFIXES="src gen test"
                ;;
            *.h)
                FUNC=c_header
                PREFIXES="src gen test"
                ;;
            *.tcl)
                FUNC=tcl_include
                PREFIXES="src gen test"
                ;;
            *.env)
                FUNC=make_env
                PREFIXES="src gen test"
                ;;
            *)
                echo "ignoring unknown file type: $FILE" >&2
                ;;
        esac 

        # Chop of typical top-level directories for source code in projects:
        SOURCE_PATH=$DIR
        for prefix in $PREFIXES; do
            SOURCE_PATH=${SOURCE_PATH#$prefix/}
        done

        # Ensure there is a directory:
        mkdir -p $DIR

        # Emit the language specific version file:
        #echo $FUNC $VC $SOURCE_PATH $FILE '-->' $FILENAME_WITH_FULL_PATH
        $FUNC $VC $SOURCE_PATH $FILE > $FILENAME_WITH_FULL_PATH
    done

    # Write version file so that it can be included in a Makefile etc.:
    echo "GIT_VERSION = $VC" > $VERSION_FILE
fi

