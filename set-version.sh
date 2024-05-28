# check if jq and sponge are installed
if ! command -v jq &> /dev/null
then
    echo "install jq and sponge"
    exit
fi

if ! command -v sponge &> /dev/null
then
    echo "install jq and sponge"
    exit
fi

jq ".version = \"$1\"" package.json | sponge package.json
jq ".version = \"$1\"" jsr.json | sponge jsr.json
