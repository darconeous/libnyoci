


### Command to get all public API symbols ###

    find . -name '*.[ch]' | xargs cat | grep ^NYOCI_API_EXTERN | sed 's/.* \([a-zA-Z0-9_]*\)(.*/\1/;s/.* \([a-zA-Z0-9_]*\);/\1/' | sort -u

